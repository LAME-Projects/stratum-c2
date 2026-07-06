"""
providers/all.py — Import every provider wizard (side-effect: populates
TRANSPORT_REGISTRY) and expose the PROVIDERS dict used by the deploy router.
"""

from providers.dropbox.wizard     import DropboxWizard
from providers.onedrive.wizard    import OneDriveWizard
from providers.s3.wizard          import S3Wizard
from providers.sharepoint.wizard  import SharePointWizard
from providers.googledrive.wizard import GoogleDriveWizard

PROVIDERS: dict = {
    "dropbox":     DropboxWizard,
    "onedrive":    OneDriveWizard,
    "s3":          S3Wizard,
    "sharepoint":  SharePointWizard,
    "googledrive": GoogleDriveWizard,
}
