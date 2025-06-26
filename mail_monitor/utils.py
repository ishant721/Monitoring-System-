# mail_monitor/utils.py

import imaplib
import logging

# Set up a logger to see detailed messages in your Django server console
logger = logging.getLogger(__name__)

def validate_imap_credentials(server: str, port: int, email: str, password: str) -> tuple[bool, str]:
    """
    Attempts to connect to an IMAP server and authenticate with the provided credentials.
    This provides immediate feedback to the user during setup.

    Args:
        server (str): The IMAP server address (e.g., 'imap.gmail.com').
        port (int): The IMAP port (e.g., 993).
        email (str): The user's full email address.
        password (str): The user's App Password.

    Returns:
        tuple[bool, str]: A tuple containing a boolean for success (True/False)
                          and a user-friendly message.
    """
    try:
        logger.info(f"Attempting to validate credentials for {email} on {server}:{port}")
        
        # Connect to the server with a reasonable timeout to prevent long hangs
        mail_connection = imaplib.IMAP4_SSL(server, port, timeout=15)
        
        # Attempt to log in
        status, response = mail_connection.login(email, password)
        
        # A successful login returns an 'OK' status
        if status == 'OK':
            logger.info(f"Successfully validated credentials for {email}")
            mail_connection.logout()
            return True, "Authentication successful."
        else:
            # This is a less common failure case where the server responds but not with 'OK'
            error_message = response[0].decode('utf-8', 'ignore') if response else "Authentication failed with a non-OK status."
            logger.warning(f"IMAP login failed for {email} with status {status}: {error_message}")
            return False, "Authentication failed. Please check your credentials and try again."

    except imaplib.IMAP4.error as e:
        # This block catches specific IMAP protocol errors, which are very useful for debugging.
        error_message = str(e).upper()
        logger.warning(f"IMAP validation error for {email}: {error_message}")
        
        # Check for common failure keywords in the error message
        if 'AUTHENTICATIONFAILED' in error_message or 'INVALID CREDENTIALS' in error_message:
            return False, "Authentication failed. Please check your email address and App Password."
        elif 'TIMED OUT' in error_message:
             return False, "The connection to the mail server timed out. Please check the server details or your network."
        else:
            return False, "Could not connect to the mail server. Please check the server address and port provided by your admin."
            
    except Exception as e:
        # This is a catch-all for other potential issues like DNS errors, timeouts, etc.
        logger.error(f"A generic exception occurred during IMAP validation for {email}: {e}")
        return False, "An unexpected error occurred while trying to connect to the mail server. Please try again later."