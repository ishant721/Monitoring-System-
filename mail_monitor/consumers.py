# mail_monitor/consumers.py

import asyncio
import imaplib
import email
from email.header import decode_header
from bs4 import BeautifulSoup
import base64
import json
import logging
from channels.consumer import AsyncConsumer
from channels.db import database_sync_to_async
from django.core.files.base import ContentFile
from django.utils.timezone import make_aware
from datetime import datetime, timedelta
import logging
import traceback
import threading
import time
from channels.generic.websocket import AsyncWebsocketConsumer
from django.utils.timezone import make_aware, now as timezone_now
from channels.layers import get_channel_layer
from asgiref.sync import sync_to_async as database_sync_to_async
from django.db import close_old_connections

from .models import EmailAccount, MonitoredEmail, EmailAttachment, CompanyEmailConfig

logger = logging.getLogger(__name__)

class MailMonitorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.room_group_name = f'mail_monitor_{self.user_id}'

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']

        # Send message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'mail_message',
                'message': message
            }
        )

    async def mail_message(self, event):
        message = event['message']

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message
        }))

listening_tasks = {}

# ==============================================================================
#  LISTENER CONTROL FUNCTIONS (The public API for other parts of Django)
# ==============================================================================

async def start_listener_for_account(account_id: int):
    """
    Starts a new monitoring task for a given account ID. If one already exists,
    it is stopped and restarted to ensure it has the latest settings.
    """
    if account_id in listening_tasks and not listening_tasks[account_id].done():
        logger.info(f"[Control] Listener for account {account_id} is running. Stopping before restart.")
        await stop_listener_for_account(account_id)
        await asyncio.sleep(1)

    logger.info(f"[Control] Creating new UID-based listener task for account ID: {account_id}")
    task = asyncio.create_task(uid_polling_loop(account_id))
    listening_tasks[account_id] = task

async def stop_listener_for_account(account_id: int):
    """Stops and cancels the monitoring task for a given account ID."""
    task = listening_tasks.pop(account_id, None)
    if task and not task.done():
        task.cancel()
        logger.info(f"[Control] Cancelled listener task for account {account_id}")

# ==============================================================================
#  UID-BASED POLLING LOOP
# ==============================================================================

async def uid_polling_loop(account_id: int):
    logger.info(f"[Acc {account_id}] Starting UID POLLING LOOP (checks every 60 seconds).")
    try:
        while account_id in listening_tasks:
            mail_connection = None
            try:
                account = await get_account_db(account_id)
                if not (account and account.is_active):
                    logger.warning(f"[Acc {account_id}] ABORT: Account inactive/deleted."); break
                password = await get_decrypted_password_db(account)
                config = await get_company_config_db(account)
                if not (password and config):
                    logger.error(f"[Acc {account_id}] FATAL: Missing credentials/config."); break
                logger.info(f"[Acc {account_id}] Connecting to {config.imap_server}...")
                mail_connection = imaplib.IMAP4_SSL(config.imap_server, config.imap_port, timeout=25)
                mail_connection.login(account.user.email, password)
                logger.info(f"[Acc {account_id}] Connection successful.")
                sent_folder = await find_sent_folder(mail_connection)
                folders_to_scan = ['INBOX']
                if sent_folder: folders_to_scan.append(sent_folder)
                for folder in folders_to_scan:
                    await fetch_and_process_with_uid(mail_connection, account, folder)
            except asyncio.CancelledError:
                logger.info(f"[Acc {account_id}] Task cancelled by admin."); break
            except Exception as e:
                logger.error(f"[Acc {account_id}] Error in polling loop: {e}. Retrying.")
            finally:
                if mail_connection:
                    try: mail_connection.logout()
                    except: pass
                await close_db_connections_async()
            logger.info(f"[Acc {account_id}] Cycle complete. Waiting 60 seconds...")
            await asyncio.sleep(60)
    finally:
        logger.warning(f"Listener loop for account {account_id} has fully terminated.")

async def fetch_and_process_with_uid(mail_connection, account, folder_name):
    try:
        # The SELECT command now correctly quotes the folder name.
        status, _ = mail_connection.select(f'"{folder_name}"', readonly=False)
        if status != 'OK':
            logger.warning(f"[Acc {account.id}] Cannot select folder '{folder_name}'.")
            return
    except Exception as e:
        logger.warning(f"[Acc {account.id}] Error selecting folder '{folder_name}': {e}"); return

    is_sent = 'sent' in folder_name.lower()
    last_uid = await get_last_uid_db(account.id, is_sent)
    search_criteria = f'(UID {last_uid + 1}:*)' if last_uid else f'(SINCE "{(datetime.now() - timedelta(days=30)).strftime("%d-%b-%Y")}")'
    logger.info(f"[Acc {account.id}] Searching folder '{folder_name}' with criteria: {search_criteria}")
    status, messages = mail_connection.uid('search', None, search_criteria)
    if status != 'OK' or not messages[0]:
        logger.info(f"[Acc {account.id}] No new emails to process in '{folder_name}'."); return

    all_uids = [int(uid) for uid in messages[0].split()]
    uids_to_process = all_uids[-100:] if last_uid is None else all_uids
    logger.info(f"[Acc {account.id}] Found {len(all_uids)} total new emails. Processing up to {len(uids_to_process)}.")

    latest_uid_processed = last_uid
    for uid in sorted(uids_to_process):
        try:
            if last_uid and uid <= last_uid: continue
            _, msg_data = mail_connection.uid('fetch', str(uid), '(RFC822)')
            if msg_data and msg_data[0]: await process_and_save_email_db(msg_data[0][1], account.id, folder_name)
            latest_uid_processed = max(latest_uid_processed or 0, uid)
        except Exception as e:
            logger.error(f"[Acc {account.id}] Failed to process UID {uid}: {e}")
    if latest_uid_processed and (not last_uid or latest_uid_processed > last_uid):
        await update_last_uid_db(account.id, latest_uid_processed, is_sent)

async def find_sent_folder(mail_connection):
    """Intelligently finds the name of the 'Sent' folder, returning it WITHOUT quotes."""
    for name in ['[Gmail]/Sent Mail', 'Sent Items', 'Sent', 'Posta inviata']:
        try:
            if mail_connection.select(f'"{name}"', readonly=True)[0] == 'OK':
                logger.info(f"Found 'Sent' folder with name: {name}")
                return name
        except: continue
    logger.warning("Could not find a standard 'Sent' folder for an account.")
    return None

# ==============================================================================
#  DATABASE AND PARSING HELPERS
# ==============================================================================
@database_sync_to_async
def close_db_connections_async(): close_old_connections()

@database_sync_to_async
def get_account_db(account_id):
    close_old_connections()
    return EmailAccount.objects.select_related('user', 'user__company_admin__email_config').filter(pk=account_id).first()

@database_sync_to_async
def get_decrypted_password_db(account): return account.get_decrypted_password()

@database_sync_to_async
def get_company_config_db(account):
    try: return account.user.company_admin.email_config
    except: return None

@database_sync_to_async
def get_last_uid_db(account_id, is_sent):
    account = EmailAccount.objects.get(pk=account_id)
    return account.last_sent_uid if is_sent else account.last_inbox_uid

@database_sync_to_async
def update_last_uid_db(account_id, uid, is_sent):
    account = EmailAccount.objects.get(pk=account_id)
    if is_sent: account.last_sent_uid = uid
    else: account.last_inbox_uid = uid
    account.save(update_fields=['last_sent_uid' if is_sent else 'last_inbox_uid'])

@database_sync_to_async
def process_and_save_email_db(raw_email_data, account_id, folder_name):
    """Process and save a single email to the database."""
    try:
        msg = email.message_from_bytes(raw_email_data)
        message_id = msg.get('Message-ID', '').strip()

        if not message_id:
            logger.warning(f"[Acc {account_id}] Skipping email without Message-ID")
            return

        # Check if email already exists
        if MonitoredEmail.objects.filter(message_id=message_id).exists():
            logger.info(f"[Acc {account_id}] Skipping duplicate email: {message_id}")
            return

        # Extract email data
        subject = decode_mime_words(msg.get('Subject', ''))
        sender = decode_mime_words(msg.get('From', ''))
        to_recipients = decode_mime_words(msg.get('To', ''))
        cc_recipients = decode_mime_words(msg.get('Cc', ''))
        bcc_recipients = decode_mime_words(msg.get('Bcc', ''))

        # Determine direction based on folder
        is_sent = 'sent' in folder_name.lower()
        direction = MonitoredEmail.Direction.OUTGOING if is_sent else MonitoredEmail.Direction.INCOMING

        # Parse date
        try:
            email_date = make_aware(email.utils.parsedate_to_datetime(msg.get('Date', '')))
        except (TypeError, ValueError):
            email_date = timezone_now()

        # Extract body and attachments
        body, attachments = extract_body_and_attachments(msg)

        # Create email record
        monitored_email = MonitoredEmail.objects.create(
            account_id=account_id,
            message_id=message_id,
            direction=direction,
            sender=sender,
            recipients_to=to_recipients,
            recipients_cc=cc_recipients,
            recipients_bcc=bcc_recipients,
            subject=subject,
            body=body,
            date=email_date,
            has_attachments=bool(attachments)
        )

        # Save attachments if any
        for attachment_data in attachments:
            EmailAttachment.objects.create(
                email=monitored_email,
                **attachment_data
            )

        logger.info(f"[Acc {account_id}] Saved {direction} email: {subject}")

    except Exception as e:
        logger.error(f"[Acc {account_id}] Error processing email: {e}")

async def find_sent_folder(mail_connection):
    """
    Intelligently finds the name of the 'Sent' folder.
    Returns the name WITHOUT quotes.
    """
    for name in ['[Gmail]/Sent Mail', 'Sent Items', 'Sent', 'Posta inviata']:
        try:
            # We add the quotes here for the command
            if mail_connection.select(f'"{name}"', readonly=True)[0] == 'OK':
                logger.info(f"Found 'Sent' folder with name: {name}")
                return name # Return the clean name
        except:
            continue
    logger.warning("Could not find a standard 'Sent' folder for an account.")
    return None

def decode_mime_words(s: str) -> str:
    if not s: return ""
    decoded_parts = []
    for text, charset in decode_header(s):
        if isinstance(text, bytes):
            decoded_parts.append(text.decode(charset or 'utf-8', 'ignore'))
        else:
            decoded_parts.append(str(text))
    return "".join(decoded_parts)

def extract_body_and_attachments(msg):
    body_html, body_plain, attachments = "", "", []
    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get("Content-Disposition"))
            if "attachment" in disposition:
                try:
                    filename = decode_mime_words(part.get_filename())
                    if filename:
                        attachments.append({'filename': filename, 'content_type': part.get_content_type(), 'file': ContentFile(part.get_payload(decode=True), name=filename)})
                except: continue
            elif part.get_content_type() == "text/html" and "attachment" not in disposition:
                try: body_html = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', 'ignore')
                except: pass
            elif part.get_content_type() == "text/plain" and "attachment" not in disposition and not body_html:
                try: body_plain = part.get_payload(decode=True).decode('utf-8', 'ignore')
                except: pass
    else:
        try: body_plain = msg.get_payload(decode=True).decode('utf-8', 'ignore')
        except: pass

    final_body = body_html or f"<html><body>{body_plain.replace('\n', '<br>')}</body></html>"
    if final_body:
        soup = BeautifulSoup(final_body, "html.parser")
        for tag in soup(["script", "style", "link", "meta", "head"]): tag.decompose()
        final_body = str(soup)
    return final_body, attachments


# ==============================================================================
#  APPLICATION STARTUP LOGIC
# ==============================================================================
_listener_loop = None

async def startup_scan_async():
    """Finds all active accounts and submits a listener task for each to the running loop."""
    logger.info("STARTUP: Submitting initial listener tasks to the manager thread...")
    @database_sync_to_async
    def get_active_accounts_ids():
        close_old_connections()
        return list(EmailAccount.objects.filter(is_active=True).values_list('id', flat=True))

    active_account_ids = await get_active_accounts_ids()
    if not active_account_ids:
        logger.info("STARTUP: No active email accounts found to monitor."); return

    for account_id in active_account_ids:
        if _listener_loop and _listener_loop.is_running():
            _listener_loop.call_soon_threadsafe(
                lambda acc_id=account_id: asyncio.create_task(start_listener_for_account(acc_id))
            )

    logger.info(f"STARTUP: Submitted {len(active_account_ids)} listener tasks.")

def run_listener_event_loop():
    """This function is the target for our background thread. It runs forever."""
    global _listener_loop
    _listener_loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_listener_loop)
    try:
        logger.info("Email listener event loop is now running in the background.")
        _listener_loop.run_forever()
    finally:
        _listener_loop.close()
        logger.info("Email listener event loop has shut down.")

def start_all_listeners_in_thread():
    """This is the main function called from apps.py to bootstrap the system."""
    manager_thread = threading.Thread(target=run_listener_event_loop, daemon=True, name="EmailListenerEventLoop")
    manager_thread.start()
    logger.info("Email listener manager background thread has been started.")

    while _listener_loop is None or not _listener_loop.is_running():
        time.sleep(0.1)

    asyncio.run_coroutine_threadsafe(startup_scan_async(), _listener_loop)

# ==============================================================================
#  THE CHANNELS CONSUMER
# ==============================================================================
class EmailListenerConsumer(AsyncConsumer):
    """
    A lightweight consumer that receives events and safely dispatches them
    to the running background event loop.
    """
    async def start_listening(self, event):
        account_id = event['account_id']
        if _listener_loop and _listener_loop.is_running():
            _listener_loop.call_soon_threadsafe(
                lambda: asyncio.create_task(start_listener_for_account(account_id))
            )

    async def stop_listening(self, event):
        account_id = event['account_id']
        if _listener_loop and _listener_loop.is_running():
            _listener_loop.call_soon_threadsafe(
                lambda: asyncio.create_task(stop_listener_for_account(account_id))
            )