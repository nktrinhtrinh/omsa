# from main import java_files, xml_files
# Data for SQLite Database search
sqlite_data = {
    "pattern": "openOrCreateDatabase|getWritableDatabase|getReadableDatabase",
    "file_extension": ".java",
    "file" : "java_files",
    "command" : "-nr -e",
    "message": "The SQLite Database Storage related instances...",
    "reference": """
        - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.
        - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information
        - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements
    """
}

# Data for Firebase Database search
firebase_data = {
    "pattern": ".firebaseio.com",
    "file_extension": ".xml",
    "file" : "xml_files",
    "message": "The Firebase Database instances...",
    "reference": """
        - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. Please note that, An attacker can read the content of the database without any authentication, if rules are set to allow open access or access is not restricted to specific users for specific data sets.
        - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
        - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements
    """
}