import asyncio
import json
import uuid
import os
import sys
import configparser
import websockets
import time
import platform
import subprocess
import base64
import io
import re
import requests
import tempfile
import logging
import aiohttp
from datetime import datetime, time as dt_time
import datetime as dt_module

# Keep all your existing data-gathering imports
import mss
from PIL import Image
import psutil
import pyscreeze
from pynput import keyboard, mouse
from websockets.protocol import State

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global timing variables
last_key_time = {}

CONFIG_FILE = "config.ini"
AGENT_ID_FILE = "agent_id.dat"

# --- CONFIGURATION (Global Variables - MUST BE AT THE TOP) ---
config = configparser.ConfigParser()
HEARTBEAT_INTERVAL = 15

if getattr(sys, 'frozen', False):
    config_path = os.path.join(sys._MEIPASS, 'config.ini')

config_data = {}

MESSAGING_APP_KEYWORDS = {
    # App Names
    "whatsapp", "messenger", "telegram", "signal", "slack", "discord", "teams",
    "outlook", "thunderbird", "skype", "zoom", "mattermost", "rocketchat",
    "element", "hexchat", "pidgin", "gajim", "zulip", "jami", "tox",
    "steam", "battle.net", "guilded", "imessage", "wechat", "line", "kakaotalk",
    "viber", "threema", "wickr", "session",
    # URL Keywords
    "web.whatsapp.com", "messenger.com", "web.telegram.org", "mail.google.com",
    "mail.yahoo.com", "outlook.live.com", "chat.google.com", "app.slack.com",
    "teams.microsoft.com", "discord.com/app", "linkedin.com/messaging",
    "twitter.com/messages", "instagram.com/direct/", "reddit.com/chat",
    "messages.google.com", "voice.google.com",
}

key_log_buffer = {}
current_typing_session = {}
completed_sessions_queue = []

# --- Global Counters ---
key_stroke_count = 0
mouse_event_count = 0
typed_keys_string = ""
last_upload_bytes = 0
last_download_bytes = 0
current_interval_ms = 10000  # Default interval in milliseconds (10 seconds)

# --- WebSocket Client Global Variable ---
websocket_client = None
_initial_auth_sent = False

# --- Recording Global Variables ---
is_recording = False
ffmpeg_process = None
recording_task = None
recording_output_file = None
ffmpeg_log_file = None

# --- Feature Bundle Flags ---
is_activity_monitoring_enabled_by_control = True
is_network_monitoring_enabled_by_control = True
is_live_streaming_enabled_by_control = False
is_keystroke_logging_enabled_by_control = False

# --- Scheduling Variables ---
is_agent_active_by_schedule = True
current_schedule = {
    "monday": {"start": None, "end": None},
    "tuesday": {"start": None, "end": None},
    "wednesday": {"start": None, "end": None},
    "thursday": {"start": None, "end": None},
    "friday": {"start": None, "end": None},
    "saturday": {"start": None, "end": None},
    "sunday": {"start": None, "end": None},
}

# --- Global configuration variables ---
BACKEND_URL = config.get('Agent', 'BACKEND_URL', fallback='http://0.0.0.0:8000')
API_KEY = config.get('Agent', 'API_KEY', fallback='')
AGENT_ID = config.get('Agent', 'AGENT_ID', fallback='')

# --- Break Management Variables ---
is_on_break = False
is_user_on_leave = False
company_breaks = []  # List of break periods
user_break_schedule = []  # User-specific break schedule

# --- Global live streaming variables ---
live_streaming_websocket = None
live_streaming_task = None

# --- FFmpeg Path ---
FFMPEG_EXECUTABLE_NAME = ""
if platform.system() == "Windows":
    FFMPEG_EXECUTABLE_NAME = "ffmpeg.exe"
else:
    FFMPEG_EXECUTABLE_NAME = "ffmpeg"

if getattr(sys, 'frozen', False):
    FFMPEG_PATH = os.path.join(sys._MEIPASS, FFMPEG_EXECUTABLE_NAME)
else:
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    FFMPEG_PATH = os.path.join(current_script_dir, FFMPEG_EXECUTABLE_NAME)
    if not os.path.exists(FFMPEG_PATH):
        print(f"WARNING: FFmpeg executable not found at '{FFMPEG_PATH}'.")
        print(f"Attempting to find '{FFMPEG_EXECUTABLE_NAME}' in system PATH.")
        FFMPEG_PATH = FFMPEG_EXECUTABLE_NAME

# --- Productive Status Thresholds ---
PRODUCTIVITY_THRESHOLD_HIGH = 10
PRODUCTIVITY_THRESHOLD_LOW = 2

# --- Launch Agent Constants (for macOS) ---
LAUNCH_AGENT_LABEL = "com.mycompany.agent"
LAUNCH_AGENT_PLIST_PATH = os.path.expanduser(f"~/Library/LaunchAgents/{LAUNCH_AGENT_LABEL}.plist")
LAUNCH_AGENT_LOG_DIR = os.path.expanduser("~/Library/Logs/MyAgent")
LAUNCH_AGENT_LOG_PATH = os.path.join(LAUNCH_AGENT_LOG_DIR, "agent.log")

# --- Local Recordings Directory ---
LOCAL_RECORDINGS_TEMP_DIR = "/Users/ishantsingh/Downloads/Monitoring-System--main-1/media/recordings"
os.makedirs(LOCAL_RECORDINGS_TEMP_DIR, exist_ok=True)

def load_config():
    config = configparser.ConfigParser()
    config_path = 'config.ini'
    if getattr(sys, 'frozen', False):
        config_path = os.path.join(sys._MEIPASS, 'config.ini')
    if not os.path.exists(config_path):
        print(f"FATAL: Configuration file '{config_path}' not found.")
        sys.exit(1)
    config.read(config_path)
    if 'Agent' not in config:
        print("FATAL: [Agent] section not found in config.ini.")
        sys.exit(1)
    return config['Agent']

def get_persistent_agent_id():
    """Reads the permanent agent ID from a local file. Returns None if not found."""
    if os.path.exists(AGENT_ID_FILE):
        with open(AGENT_ID_FILE, 'r') as f:
            return f.read().strip()
    return None

def save_persistent_agent_id(agent_id):
    """Saves the permanent agent ID to a local file after successful pairing."""
    with open(AGENT_ID_FILE, 'w') as f:
        f.write(agent_id)
    print(f"Agent successfully paired. Permanent ID '{agent_id}' saved to {AGENT_ID_FILE}")

def execute_osascript(script):
    """Helper to execute AppleScript on macOS and capture errors."""
    try:
        process = subprocess.run(
            ['osascript', '-e', script],
            capture_output=True,
            text=True,
            check=True
        )
        return process.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"AppleScript failed with exit code {e.returncode}.")
        print(f"AppleScript executed: {script}")
        print(f"Stderr: {e.stderr.strip()}")
        return ""
    except Exception as e:
        print(f"Error executing AppleScript: {e}")
        return ""

def get_active_window_info():
    app_name = "Unknown App"
    website_url = ""

    system = platform.system()

    if system == "Darwin":  # macOS
        try:
            app_name = execute_osascript("tell application (path to frontmost application as text) to get name of it")
            if not app_name:
                app_name = "Idle"

            chrome_family_browsers = ["Google Chrome", "Brave Browser", "Microsoft Edge", "Chromium", "Vivaldi"]
            if app_name in chrome_family_browsers:
                for browser_name in [app_name, "Google Chrome", "Brave Browser", "Microsoft Edge"]:
                    is_running = execute_osascript(f'tell application "{browser_name}" to get running')
                    if is_running.lower() == "true":
                        url_script = f'tell application "{browser_name}" to get URL of active tab of window 1'
                        website_url = execute_osascript(url_script)
                        if website_url:
                            break

            elif app_name == "Safari":
                is_running = execute_osascript('tell application "Safari" to get running')
                if is_running.lower() == "true":
                    url_script = 'tell application "Safari" to get URL of front document'
                    website_url = execute_osascript(url_script)

            elif app_name == "Firefox":
                is_running = execute_osascript('tell application "Firefox" to get running')
                if is_running.lower() == "true":
                    window_title_script = 'tell application "Firefox" to get name of front window'
                    window_title = execute_osascript(window_title_script)
                    match = re.search(r'https?://[^\s/$.?#].[^\s]*', window_title)
                    if match:
                        website_url = match.group(0)

        except Exception as e:
            print(f"Error getting active window info (macOS): {e}")
            app_name = "Unknown App (macOS Error)"
            website_url = ""

    elif system == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL('user32')
            kernel32 = ctypes.WinDLL('kernel32')

            hwnd = user32.GetForegroundWindow()

            pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))

            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            window_title_fallback = buf.value

            try:
                proc = psutil.Process(pid.value)
                app_name = proc.name()
            except psutil.NoSuchProcess:
                app_name = "Unknown Process"
            except Exception as e:
                print(f"Error getting process name: {e}")
                app_name = "Unknown Process"

            if not app_name:
                app_name = window_title_fallback or "Idle"

        except Exception as e:
            print(f"Error getting active window info (Windows): {e}")
            app_name = "Unknown App (Windows Error)"
        website_url = ""

    elif system == "Linux":
        try:
            app_name = subprocess.check_output(['xdotool', 'getwindowfocus', 'getwindowname']).decode('utf-8').strip()
            if not app_name:
                app_name = "Idle"
            website_url = ""
        except subprocess.CalledProcessError:
            app_name = "Unknown App (xdotool missing?)"
            website_url = ""
        except Exception as e:
            print(f"Error getting active window info (Linux): {e}")
            app_name = "Unknown App (Linux Error)"

    return app_name, website_url

def is_messaging_app(app_name, url):
    """Checks if the app name or URL corresponds to a known messaging app."""
    if app_name:
        app_lower = app_name.lower()
        for keyword in MESSAGING_APP_KEYWORDS:
            if keyword in app_lower:
                return True
    if url:
        url_lower = url.lower()
        for keyword in MESSAGING_APP_KEYWORDS:
            if keyword in url_lower:
                return True
    return False

def on_key_press(key):
    global key_stroke_count, key_log_buffer, last_key_time, typed_keys_string

    # Skip if agent is on break or user is on leave
    if is_on_break or is_user_on_leave:
        return

    key_stroke_count += 1

    # Always capture typed keys for the heartbeat even if detailed logging is disabled
    try:
        key_char = key.char
        if key_char and key_char.isprintable():
            typed_keys_string += key_char
    except AttributeError:
        pass  # Special keys like Ctrl, Alt, etc.

    # Only capture detailed keystroke logs if keystroke logging is enabled
    if not is_keystroke_logging_enabled_by_control:
        logger.debug(f"Keystroke logging disabled. Current flag: {is_keystroke_logging_enabled_by_control}")
        return

    app_name, website_url = get_active_window_info()
    source_id = website_url or app_name or "Unknown"

    if source_id not in key_log_buffer:
        key_log_buffer[source_id] = {
            'keys': [],
            'is_messaging': is_messaging_app(app_name, website_url)
        }

    try:
        key_str = key.char
        if key_str and key_str.isprintable():
            pass  # Use the character as-is
        else:
            key_str = None  # Skip non-printable characters for detailed logging
    except AttributeError:
        key_str = f'[{str(key).replace("Key.", "").upper()}]'

    if key_str:  # Only log if we have a valid key string
        # Optional deduplication logic (within 0.1s)
        now = time.time()
        if last_key_time.get(source_id, {}).get(key_str, 0) + 0.1 > now:
            return  # skip duplicate key
        last_key_time.setdefault(source_id, {})[key_str] = now

        key_log_buffer[source_id]['keys'].append(key_str)

def on_click(x, y, button, pressed):
    """Callback for mouse click events."""
    global mouse_event_count
    if pressed:
        mouse_event_count += 1

def on_scroll(x, y, dx, dy):
    """Callback for mouse scroll events."""
    global mouse_event_count
    mouse_event_count += 1

def end_typing_session():
    """Finalizes the current session and moves it to the send queue."""
    global current_typing_session, completed_sessions_queue
    if current_typing_session and current_typing_session.get('keys'):
        print(f"INFO: Typing session for '{current_typing_session['source']}' ended. Queued for sending.")
        completed_sessions_queue.append(current_typing_session)
    current_typing_session = {}

def capture_screenshot_base64():
    """
    Captures a screenshot and returns ONLY the raw Base64 encoded string.
    The data URI header will be added on the server side to prevent issues.
    """
    try:
        with mss.mss() as sct:
            sct_img = sct.grab(sct.monitors[1])  # Primary monitor

            # Convert to a PIL Image object
            img = Image.frombytes("RGB", sct_img.size, sct_img.rgb)

            # Save the image to a memory buffer
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")

            # Encode the buffer's content to Base64 and return JUST the string
            return base64.b64encode(buffered.getvalue()).decode('utf-8')

    except Exception as e:
        print(f"ERROR: An unexpected error occurred during screenshot capture: {e}")
        return None

def capture_raw_frame():
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[0]
            sct_img = sct.grab(monitor)
            return sct_img.rgb, sct_img.size
    except Exception as e:
        print(f"Error capturing raw frame: {e}")
        return None, (0, 0)

def get_total_bandwidth_usage():
    """Gets total bytes sent and received from all network interfaces."""
    try:
        return psutil.net_io_counters()
    except Exception as e:
        print(f"Error getting bandwidth, returning zero values: {e}")
        return psutil._common.snetio(bytes_sent=0, bytes_recv=0, packets_sent=0, packets_recv=0, errin=0, errout=0, dropin=0, dropout=0)

def get_network_type():
    """Infers the network connection type (Wi-Fi, Ethernet, Mobile) based on interface names."""
    network_type = "Unknown"
    active_interface_name = "N/A"

    try:
        interfaces = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        import socket
        AF_INET = socket.AF_INET

        for iface_name, iface_stats in interfaces.items():
            if iface_stats.isup:
                has_real_address = False
                if iface_name in addrs:
                    for snet in addrs[iface_name]:
                        if snet.family == AF_INET and snet.address != '127.0.0.1':
                            has_real_address = True
                            break

                if not has_real_address:
                    continue

                if platform.system() == "Darwin":  # macOS
                    if iface_name.startswith("en"):
                        output = subprocess.getoutput('networksetup -listallhardwareports')
                        if "Wi-Fi" in output and f"Device: {iface_name}" in subprocess.getoutput(f'networksetup -getmacaddress "{iface_name}"').strip():
                            network_type = "Wi-Fi"
                        elif "Ethernet" in output and f"Device: {iface_name}" in subprocess.getoutput(f'networksetup -getmacaddress "{iface_name}"').strip():
                            network_type = "Ethernet"
                        elif iface_name.startswith("pdp_ip"):
                            network_type = "Mobile"
                        elif iface_name.startswith("utun"):
                            network_type = "VPN/Tether"
                        else:
                            network_type = "Wired/Wireless"
                    elif iface_name.startswith("bridge"):
                        network_type = "Mobile/Tether"

                elif platform.system() == "Windows":
                    if iface_name.lower().startswith("wi-fi") or "wireless" in iface_name.lower():
                        network_type = "Wi-Fi"
                    elif iface_name.lower().startswith("ethernet") or "lan" in iface_name.lower():
                        network_type = "Ethernet"
                    elif "mobile broadband" in iface_name.lower() or "cellular" in iface_name.lower():
                        network_type = "Mobile"
                    elif "usb" in iface_name.lower() and iface_stats.isup:
                        network_type = "Mobile/Tether"

                elif platform.system() == "Linux":
                    if iface_name.startswith("wlan") or iface_name.startswith("wl"):
                        network_type = "Wi-Fi"
                    elif iface_name.startswith("eth") or iface_name.startswith("en"):
                        network_type = "Ethernet"
                    elif iface_name.startswith("usb") or iface_name.startswith("wwan"):
                        network_type = "Mobile/Tether"

                if network_type != "Unknown":
                    active_interface_name = iface_name
                    break

        return f"{network_type} ({active_interface_name})"

    except Exception as e:
        print(f"Error getting network type: {e}")
        return "Unknown"

async def pair_with_server(config):
    """Handles the one-time pairing process for a new agent installation."""
    logger.info("--- Agent First-Time Setup: Pairing Mode ---")
    pairing_token = input("Please enter the one-time pairing token from the web dashboard: ").strip()
    if not pairing_token:
        logger.error("Pairing token cannot be empty. Exiting.")
        return None

    new_agent_id = str(uuid.uuid4())
    base_ws_url = config['base_url'].replace('http', 'ws', 1)
    pairing_url = f"{base_ws_url}/monitor/ws/agent/pairing/"

    logger.info(f"Connecting to {pairing_url} to pair with new ID: {new_agent_id}")
    try:
        async with websockets.connect(pairing_url) as websocket:
            pair_request = {
                "type": "pair_agent",
                "pairing_token": pairing_token,
                "agent_id": new_agent_id
            }
            await websocket.send(json.dumps(pair_request))
            response_str = await websocket.recv()
            response = json.loads(response_str)

            if response.get("type") == "pairing_success":
                save_persistent_agent_id(new_agent_id)
                logger.info(f"Agent successfully paired with ID: {new_agent_id}")
                return new_agent_id
            else:
                logger.error(f"Pairing Failed: {response.get('reason', 'Unknown error from server')}")
                return None
    except Exception as e:
        logger.error(f"Error during pairing process: {e}")
        return None

async def _start_recording_loop(output_path, fps=15):
    """Internal function to run the screen capture and FFmpeg process."""
    global is_recording, ffmpeg_process, ffmpeg_log_file

    print(f"Starting recording loop to {output_path} at {fps} FPS...")

    _, (width, height) = capture_raw_frame()
    if width == 0 or height == 0:
        print("Failed to get screen resolution, cannot start recording.")
        is_recording = False
        await send_control_response(False, "Recording failed: Could not get screen resolution.")
        return

    command = [
        FFMPEG_PATH,
        '-y',
        '-f', 'rawvideo',
        '-pix_fmt', 'rgb24',
        '-s', f"{width}x{height}",
        '-r', str(fps),
        '-i', 'pipe:0',
        '-c:v', 'libx264',
        '-preset', 'ultrafast',
        '-crf', '23',
        '-vf', 'format=yuv420p',
        output_path
    ]

    try:
        log_filename = f"{os.path.basename(output_path)}.ffmpeg_log.txt"
        ffmpeg_log_file_path = os.path.join(LOCAL_RECORDINGS_TEMP_DIR, log_filename)
        ffmpeg_log_file = open(ffmpeg_log_file_path, "a")

        ffmpeg_process = await asyncio.create_subprocess_exec(
            *command,
            stdin=subprocess.PIPE,
            stdout=ffmpeg_log_file,
            stderr=subprocess.STDOUT
        )
        print(f"FFmpeg subprocess started for recording. Log: {ffmpeg_log_file_path}")

        frame_delay = 1.0 / fps
        while is_recording and ffmpeg_process.returncode is None:
            frame_data, (f_width, f_height) = capture_raw_frame()
            if frame_data:
                try:
                    ffmpeg_process.stdin.write(frame_data)
                    await ffmpeg_process.stdin.drain()
                except BrokenPipeError:
                    print("BrokenPipeError: FFmpeg process stdin pipe closed. FFmpeg likely terminated unexpectedly.")
                    break
                except Exception as e:
                    print(f"Error writing frame to FFmpeg: {e}")
                    break
            await asyncio.sleep(frame_delay)

    except FileNotFoundError:
        print(f"Error: FFmpeg not found at '{FFMPEG_PATH}'. Please ensure FFmpeg is bundled or installed.")
        is_recording = False
        await send_control_response(False, "Recording failed: FFmpeg executable not found.")
    except Exception as e:
        print(f"Error in recording loop: {e}")
        is_recording = False
        await send_control_response(False, f"Recording error: {str(e)}")
    finally:
        if ffmpeg_process and ffmpeg_process.returncode is None:
            print("Terminating FFmpeg subprocess.")
            ffmpeg_process.stdin.close()
            try:
                await asyncio.wait_for(ffmpeg_process.wait(), timeout=10)
            except asyncio.TimeoutError:
                print("FFmpeg did not terminate cleanly, killing process.")
                ffmpeg_process.kill()

        ffmpeg_process = None
        is_recording = False

        if ffmpeg_log_file:
            ffmpeg_log_file.close()
            ffmpeg_log_file = None

        print("Recording loop finished.")

        if output_path and os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            print(f"Recording file created: {output_path} ({os.path.getsize(output_path)} bytes). Initiating upload.")
            asyncio.create_task(upload_recording_file(output_path))
        else:
            print(f"Recording file not found or is empty after stopping: {output_path}")
            await send_control_response(False, f"Recording stopped but file empty/missing: {os.path.basename(output_path)}")

async def start_recording():
    global is_recording, recording_task, recording_output_file

    if is_recording:
        print("Recording is already active.")
        await send_control_response(False, "Recording already active.")
        return

    if not is_agent_active_by_schedule:
        print("Recording commands ignored: Agent is currently outside active schedule.")
        await send_control_response(False, "Recording ignored: Outside active schedule.")
        return

    print("Starting screen recording...")
    is_recording = True

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    recording_output_file = os.path.join(LOCAL_RECORDINGS_TEMP_DIR, f"{AGENT_ID}_recording_{timestamp}.mp4")

    recording_task = asyncio.create_task(_start_recording_loop(recording_output_file))
    print(f"Recording task launched to: {recording_output_file}")
    await send_control_response(True, f"Recording started to {os.path.basename(recording_output_file)}")

async def stop_recording():
    global is_recording, ffmpeg_process, recording_task, recording_output_file

    if not is_recording:
        print("No active recording to stop.")
        await send_control_response(False, "No recording active.")
        return

    print("Stopping screen recording...")
    is_recording = False

    if recording_task and not recording_task.done():
        try:
            await asyncio.wait_for(recording_task, timeout=15)
        except asyncio.TimeoutError:
            print("Recording stop task did not finish in time, force stopping FFmpeg.")
            if ffmpeg_process and ffmpeg_process.returncode is None:
                ffmpeg_process.kill()

    recording_output_file = None

async def upload_recording_file(file_path):
    print(f"Attempting to upload recording: {file_path}")
    if not os.path.exists(file_path):
        print(f"Error: File not found for upload: {file_path}")
        await send_control_response(False, f"Upload failed: File not found {os.path.basename(file_path)}")
        return

    if os.path.getsize(file_path) == 0:
        print(f"Error: Attempted to upload empty file: {file_path}. Deleting.")
        os.remove(file_path)
        await send_control_response(False, f"Upload failed: Empty file {os.path.basename(file_path)}")
        return

    try:
        with open(file_path, 'rb') as f:
            files = {'video_file': (os.path.basename(file_path), f, 'video/mp4')}
            data = {'agent_id': AGENT_ID}
            headers = {"X-API-KEY": API_KEY, "X-AGENT-ID": AGENT_ID}

            loop = asyncio.get_running_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.post(f"{BACKEND_URL}/api/upload_recording/", files=files, data=data, headers=headers, timeout=600)
            )
        response.raise_for_status()
        print(f"Successfully uploaded {os.path.basename(file_path)}. Server response: {response.status_code}")
        await send_control_response(True, f"Recording uploaded: {os.path.basename(file_path)}")
        os.remove(file_path)
        print(f"Deleted local recording file: {file_path}")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading recording {os.path.basename(file_path)}: {e}")
        error_msg = f"Upload failed: {os.path.basename(file_path)} - HTTP Error {e.response.status_code}" if hasattr(e, 'response') else f"Upload failed: {str(e)}"
        await send_control_response(False, error_msg)
    except Exception as e:
        print(f"General error during recording upload: {e}")
        await send_control_response(False, f"Upload failed (internal error): {os.path.basename(file_path)} - {str(e)}")

async def send_control_response(status_ok, message):
    """Helper to send a control response back to the backend."""
    global websocket_client
    if websocket_client and websocket_client.state == State.OPEN:
        try:
            response_message = {
                "type": "control_response",
                "agent_id": AGENT_ID,
                "status": "success" if status_ok else "failure",
                "message": message
            }
            await websocket_client.send(json.dumps(response_message))
        except Exception as e:
            print(f"Failed to send control response: {e}")

def install_launch_agent():
    if not (getattr(sys, 'frozen', False) and platform.system() == "Darwin"):
        print("Not running as a frozen app on macOS, skipping launch agent installation.")
        return

    if os.path.exists(LAUNCH_AGENT_PLIST_PATH):
        print("Launch agent already installed.")
        return

    print("Installing launch agent...")

    executable_path_in_bundle = os.path.abspath(sys.executable)

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCH_AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable_path_in_bundle}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LAUNCH_AGENT_LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{LAUNCH_AGENT_LOG_PATH}</string>
</dict>
</plist>
"""
    try:
        os.makedirs(os.path.dirname(LAUNCH_AGENT_PLIST_PATH), exist_ok=True)
        os.makedirs(LAUNCH_AGENT_LOG_DIR, exist_ok=True)

        with open(LAUNCH_AGENT_PLIST_PATH, "w") as f:
            f.write(plist_content)

        subprocess.run(["launchctl", "load", "-w", LAUNCH_AGENT_PLIST_PATH], check=True)
        print(f"Launch agent installed successfully at {LAUNCH_AGENT_PLIST_PATH}")
        print(f"Agent output will be logged to {LAUNCH_AGENT_LOG_PATH}")

    except subprocess.CalledProcessError as e:
        print(f"Error loading launch agent with launchctl: {e}")
        print(f"Stderr: {e.stderr.decode().strip()}")
    except Exception as e:
        print(f"Error installing launch agent: {e}")

async def disconnect_websocket():
    global websocket_client
    if websocket_client and websocket_client.state == State.OPEN:
        await websocket_client.close()
        print("WebSocket disconnected.")
    websocket_client = None

def is_within_active_schedule():
    """
    Checks if the current SYSTEM LOCAL TIME is within the active schedule for the current day.
    Returns True if active, False otherwise.
    """
    global current_schedule

    if not current_schedule:
        return True

    now_local = datetime.now()
    today_weekday_str = now_local.strftime('%A').lower()

    day_schedule = current_schedule.get(today_weekday_str, {"start": None, "end": None})

    start_time_str = day_schedule.get("start")
    end_time_str = day_schedule.get("end")

    if not start_time_str or not end_time_str:
        return True

    try:
        start_time = dt_module.datetime.strptime(start_time_str, "%H:%M").time()
        end_time = dt_module.datetime.strptime(end_time_str, "%H:%M").time()

        current_time = now_local.time()

        if start_time <= end_time:
            return start_time <= current_time <= end_time
        else:
            return current_time >= start_time or current_time <= end_time

    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid time format in schedule for {today_weekday_str} ('{start_time_str}'-'{end_time_str}'). Error: {e}")
        return True

def check_break_status():
    """
    Checks if the agent should be on break based on company and user break schedules.
    Also stops all monitoring activities when on break.
    """
    global is_on_break, is_user_on_leave, company_breaks, user_break_schedule
    global is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control
    global is_live_streaming_enabled_by_control, is_keystroke_logging_enabled_by_control

    now = datetime.now()
    current_time = now.time()
    current_day = now.strftime('%A').lower()

    logger.debug(f"Checking break status at {current_time} on {current_day}")

    was_on_break = is_on_break

    # Check if user is on leave
    if is_user_on_leave:
        if not is_on_break:
            logger.info("User is on leave - entering break mode")
            is_on_break = True
            _stop_all_monitoring_activities("User is on leave")
        return True

    # Check company-wide breaks
    for break_period in company_breaks:
        break_day = break_period.get('day', '').lower()
        if break_day == current_day or break_day == 'daily':
            try:
                start_time_str = break_period.get('start_time', break_period.get('start'))
                end_time_str = break_period.get('end_time', break_period.get('end'))

                if not start_time_str or not end_time_str:
                    continue

                # Handle both time objects and string formats
                if isinstance(start_time_str, str):
                    start_time = dt_module.datetime.strptime(start_time_str, "%H:%M").time()
                else:
                    start_time = start_time_str

                if isinstance(end_time_str, str):
                    end_time = dt_module.datetime.strptime(end_time_str, "%H:%M").time()
                else:
                    end_time = end_time_str

                # Handle breaks that span midnight
                if start_time <= end_time:
                    # Normal break within same day
                    is_in_break = start_time <= current_time <= end_time
                else:
                    # Break spans midnight
                    is_in_break = current_time >= start_time or current_time <= end_time

                if is_in_break:
                    if not is_on_break:
                        logger.info(f"Entering company break: {break_period.get('name', 'Break')} ({start_time}-{end_time})")
                        is_on_break = True
                        _stop_all_monitoring_activities(f"Company break: {break_period.get('name', 'Break')}")
                    return True

            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid time format in company break schedule: {break_period}. Error: {e}")
                continue

    # Check user-specific breaks for current day only
    for break_period in user_break_schedule:
        break_day = break_period.get('day', '').lower()
        is_active = break_period.get('is_active', True)

        if not is_active:
            continue

        # Only check breaks for current day or daily breaks
        if break_day == current_day or break_day == 'daily':
            try:
                start_time_str = break_period.get('start_time', break_period.get('start'))
                end_time_str = break_period.get('end_time', break_period.get('end'))

                if not start_time_str or not end_time_str:
                    continue

                # Handle both time objects and string formats
                if isinstance(start_time_str, str):
                    start_time = dt_module.datetime.strptime(start_time_str, "%H:%M").time()
                else:
                    start_time = start_time_str

                if isinstance(end_time_str, str):
                    end_time = dt_module.datetime.strptime(end_time_str, "%H:%M").time()
                else:
                    end_time = end_time_str

                # Handle breaks that span midnight
                if start_time <= end_time:
                    # Normal break within same day
                    is_in_break = start_time <= current_time <= end_time
                else:
                    # Break spans midnight
                    is_in_break = current_time >= start_time or current_time <= end_time

                if is_in_break:
                    if not is_on_break:
                        logger.info(f"Entering user break: {break_period.get('name', 'Break')} ({start_time}-{end_time})")
                        is_on_break = True
                        _stop_all_monitoring_activities(f"User break: {break_period.get('name', 'Break')}")
                    return True

            except (ValueError, TypeError) as e:
                logger.warning(f"Invalid time format in user break schedule: {break_period}. Error: {e}")
                continue

    # If we were on break but no longer should be
    if was_on_break and not is_on_break:
        logger.info("Break period ended, resuming monitoring")
        is_on_break = False
        _resume_all_monitoring_activities()

    return False


def _stop_all_monitoring_activities(reason):
    """
    Stops all monitoring activities when entering break mode.
    """
    global is_recording, live_streaming_task

    logger.info(f"Stopping all monitoring activities: {reason}")

    # Stop live streaming if active
    if live_streaming_task and not live_streaming_task.done():
        asyncio.create_task(stop_live_streaming())

    # Stop recording if active
    if is_recording:
        asyncio.create_task(stop_recording())

    logger.info("All monitoring activities stopped for break period")


def _resume_all_monitoring_activities():
    """
    Resumes monitoring activities when break period ends.
    """
    logger.info("Break period ended - monitoring activities can resume based on configuration")
    # Note: Activities will resume automatically based on their enabled flags
    # No need to explicitly restart them here as the heartbeat loop handles this

def update_break_schedules(config_data):
    """
    Updates break schedules from server configuration.
    """
    global company_breaks, user_break_schedule, is_user_on_leave

    company_breaks = config_data.get('company_breaks', [])
    user_break_schedule = config_data.get('user_break_schedule', [])
    is_user_on_leave = config_data.get('is_user_on_leave', False)

    logger.info("=== BREAK SCHEDULE UPDATE ===")
    if company_breaks:
        logger.info(f"Updated company break schedule: {len(company_breaks)} break periods")
        for idx, break_period in enumerate(company_breaks):
            logger.info(f"  Company Break {idx+1}: {break_period.get('name', 'Unnamed')} - {break_period.get('day', 'N/A')} ({break_period.get('start', 'N/A')}-{break_period.get('end', 'N/A')})")
    else:
        logger.info("No company break schedules configured")

    if user_break_schedule:
        logger.info(f"Updated user break schedule: {len(user_break_schedule)} break periods")
        for idx, break_period in enumerate(user_break_schedule):
            logger.info(f"  User Break {idx+1}: {break_period.get('name', 'Unnamed')} - {break_period.get('day', 'N/A')} ({break_period.get('start', 'N/A')}-{break_period.get('end', 'N/A')})")
    else:
        logger.info("No user-specific break schedules configured")

    if is_user_on_leave:
        logger.info("User is marked as on leave - monitoring suspended")
    else:
        logger.info("User is not on leave")
    logger.info("=== END BREAK SCHEDULE UPDATE ===")

# Placing the live streaming functions before websocket_message_handler to resolve the error
async def start_live_streaming():
    """Starts the live streaming task if it's enabled and not already running."""
    global live_streaming_task

    print("DEBUG: start_live_streaming() called.")
    if not is_live_streaming_enabled_by_control:
        print("DEBUG: Live streaming is disabled by control, cannot start.")
        await send_control_response(False, "Live streaming is disabled by configuration.")
        return

    if live_streaming_task and not live_streaming_task.done():
        print("DEBUG: Live streaming task is already running.")
        await send_control_response(False, "Live streaming is already active.")
        return

    print("INFO: Control command accepted. Starting live stream task.")
    live_streaming_task = asyncio.create_task(live_streaming_loop())
    await send_control_response(True, "Live streaming initiated.")


async def stop_live_streaming():
    """Stops the live streaming task if it is running."""
    global live_streaming_task, live_streaming_websocket

    print("DEBUG: stop_live_streaming() called.")
    if live_streaming_websocket:
        print("INFO: Closing live streaming websocket.")
        await live_streaming_websocket.close()
        live_streaming_websocket = None

    if live_streaming_task and not live_streaming_task.done():
        print("INFO: Cancelling live streaming task.")
        live_streaming_task.cancel()
        try:
            await live_streaming_task
        except asyncio.CancelledError:
            print("INFO: Live streaming task successfully cancelled.")
        live_streaming_task = None
    else:
        print("DEBUG: No active live stream task to stop.")

    await send_control_response(True, "Live streaming stopped.")


def _install_opencv_non_blocking():
    """Synchronous function to be run in a separate thread to avoid blocking asyncio loop."""
    print("OpenCV/Numpy not found. Attempting to install non-blockingly...")
    try:
        process = subprocess.run(
            [sys.executable, "-m", "pip", "install", "opencv-python", "numpy"],
            check=True, capture_output=True, text=True
        )
        print("INFO: OpenCV and NumPy installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"FATAL: Failed to install OpenCV. Pip stderr:\n{e.stderr}")
        return False
    except Exception as e:
        print(f"FATAL: An unexpected error occurred during OpenCV installation: {e}")
        return False


async def live_streaming_loop():
    """The main loop for capturing and sending screen frames for live streaming."""
    global live_streaming_websocket, is_live_streaming_enabled_by_control

    # --- Dependency Check ---
    try:
        import cv2
        import numpy as np
    except ImportError:
        installed_ok = await asyncio.to_thread(_install_opencv_non_blocking)
        if not installed_ok:
            is_live_streaming_enabled_by_control = False # Disable to prevent retries
            await send_control_response(False, "Live streaming failed: could not install dependencies.")
            return
        import cv2
        import numpy as np

    # --- Connection and Authentication ---
    base_ws_url = BACKEND_URL.replace('http', 'ws', 1)
    streaming_url = f"{base_ws_url}/ws/stream/agent/{AGENT_ID}/"
    print(f"DEBUG: [Live Stream] Attempting to connect to: {streaming_url}")

    try:
        async with websockets.connect(streaming_url) as websocket:
            live_streaming_websocket = websocket
            print("INFO: [Live Stream] WebSocket connection established. Authenticating...")

            ### =============================================================== ###
            ### CRITICAL FIX: SEND AUTHENTICATION PAYLOAD ON THE STREAMING SOCKET ###
            ### =============================================================== ###
            auth_payload = {
                "type": "auth",
                "api_key": API_KEY,
                "agent_id": AGENT_ID
            }
            await websocket.send(json.dumps(auth_payload))

            # Optional: Wait for an auth_success message from the backend.
            # This makes the connection more robust.
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                response_data = json.loads(response)
                if response_data.get("status") != "auth_success":
                    print(f"ERROR: [Live Stream] Authentication failed: {response_data.get('reason')}")
                    return # Exit the loop if auth fails
            except asyncio.TimeoutError:
                print("WARNING: [Live Stream] Did not receive auth confirmation from server in 5s. Proceeding anyway.")
            except Exception as e:
                 print(f"ERROR: [Live Stream] Error receiving auth confirmation: {e}")
                 return

            print("INFO: [Live Stream] Authentication successful. Starting frame transmission.")

            # --- Frame Processing Loop ---
            while is_live_streaming_enabled_by_control:
                try:
                    frame_data, (width, height) = capture_raw_frame()
                    if not frame_data:
                        await asyncio.sleep(0.5)
                        continue

                    frame_np = np.frombuffer(frame_data, dtype=np.uint8).reshape((height, width, 3))
                    frame_bgr = cv2.cvtColor(frame_np, cv2.COLOR_RGB2BGR)

                    scale_percent = min(1.0, 720 / height)
                    if scale_percent < 1.0:
                        new_width = int(width * scale_percent)
                        new_height = int(height * scale_percent)
                        frame_resized = cv2.resize(frame_bgr, (new_width, new_height), interpolation=cv2.INTER_AREA)
                    else:
                        frame_resized = frame_bgr

                    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 85]
                    result, buffer = cv2.imencode('.jpg', frame_resized, encode_param)

                    if result:
                        await websocket.send(buffer.tobytes())

                    await asyncio.sleep(0.1) # Target ~10 FPS

                except websockets.exceptions.ConnectionClosed:
                    print("ERROR: [Live Stream] Connection closed by server during frame sending.")
                    break # Exit the inner while loop
                except Exception as e:
                    print(f"ERROR: [Live Stream] An error occurred inside the frame processing loop: {e}")
                    await asyncio.sleep(1) # Wait a bit before retrying

    except asyncio.CancelledError:
        print("INFO: [Live Stream] Loop was cancelled.")
    except websockets.exceptions.InvalidURI:
        print(f"ERROR: [Live Stream] The WebSocket URI is invalid: {streaming_url}")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"ERROR: [Live Stream] Connection failed. The server may have rejected the connection. Reason: {e}")
    except Exception as e:
        print(f"FATAL: [Live Stream] An unhandled error occurred in the connection block: {e}")
    finally:
        print("INFO: [Live Stream] Loop has terminated.")
        live_streaming_websocket = None

# Replace your existing websocket_message_handler with this one.

async def websocket_message_handler():
    """
    Handles all incoming messages from the control WebSocket.
    Processes direct commands and global configuration updates, reconciling the agent's state.
    """
    global websocket_client, is_recording, ffmpeg_process, recording_task, \
           is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, \
           is_live_streaming_enabled_by_control, current_interval_ms, current_schedule, live_streaming_task

    while True:
        # Loop only if the websocket client exists and is open
        if websocket_client and websocket_client.state == State.OPEN:
            try:
                message = await websocket_client.recv()
                data = json.loads(message)

                # Ensure the message is a control command
                if data.get("type") != "control":
                    print(f"INFO: Received non-control message, ignoring: {data.get('type')}")
                    continue

                action = data.get("action")
                feature_bundle = data.get("feature_bundle")
                print(f"Received control command: {data}")

                # --- Handler for direct start/stop commands ---
                if action in ["start", "stop"] and feature_bundle:
                    if feature_bundle == "live_streaming":
                        if action == "start":
                            asyncio.create_task(start_live_streaming())
                        elif action == "stop":
                            asyncio.create_task(stop_live_streaming())
                    elif feature_bundle == "screen_recording":
                        if action == "start":
                            await start_recording()
                        elif action == "stop":
                            await stop_recording()
                    else:
                        await send_control_response(False, f"Unknown feature_bundle '{feature_bundle}' for start/stop action.")

                # --- Handler for enabling/disabling features ---
                elif action in ["enable", "disable"] and feature_bundle:
                    new_state = (action == "enable")
                    if feature_bundle == "activity_monitoring":
                        is_activity_monitoring_enabled_by_control = new_state
                        print(f"Command: Activity Monitoring {'Enabled' if new_state else 'Disabled'}.")
                        await send_control_response(True, f"Activity monitoring {'enabled' if new_state else 'disabled'}.")
                    elif feature_bundle == "network_monitoring":
                        is_network_monitoring_enabled_by_control = new_state
                        print(f"Command: Network Monitoring {'Enabled' if new_state else 'Disabled'}.")
                        await send_control_response(True, f"Network monitoring {'enabled' if new_state else 'disabled'}.")
                    elif feature_bundle == "keystroke_logging":
                        is_keystroke_logging_enabled_by_control = new_state
                        print(f"Command: Keystroke Logging {'Enabled' if new_state else 'Disabled'}.")
                        await send_control_response(True, f"Keystroke logging {'enabled' if new_state else 'disabled'}.")
                    else:
                        await send_control_response(False, f"Unknown feature_bundle '{feature_bundle}' for enable/disable action.")

                # --- Handler for interval changes ---
                elif action == "set" and feature_bundle == "interval_control":
                    new_interval = data.get("interval")
                    if new_interval and new_interval > 0:
                        current_interval_ms = new_interval * 1000
                        print(f"Command: Set interval to {new_interval} seconds.")
                        await send_control_response(True, f"Interval set to {new_interval} seconds.")
                    else:
                        await send_control_response(False, "Invalid interval value provided.")

                # --- Handler for emergency stop commands ---
                elif action == "emergency_stop" or data.get("type") == "emergency_stop":
                    logger.critical(f"EMERGENCY STOP received: {data.get('reason', 'No reason provided')}")

                    # Immediately disable all monitoring
                    is_activity_monitoring_enabled_by_control = False
                    is_network_monitoring_enabled_by_control = False
                    is_live_streaming_enabled_by_control = False
                    is_keystroke_logging_enabled_by_control = False

                    # Stop any active tasks
                    if live_streaming_task and not live_streaming_task.done():
                        await stop_live_streaming()

                    if is_recording:
                        await stop_recording()

                    logger.info("All monitoring activities stopped due to emergency stop command")
                    await send_control_response(True, "Emergency stop executed - all monitoring disabled")

                    # Optionally disconnect after emergency stop
                    # await disconnect_websocket()
                    return

                # --- Handler for global configuration updates (most robust) ---
                elif action == "set_global_config":
                    logger.info("Processing global config update...")

                    # 1. Update all internal configuration variables from the payload
                    if data.get("capture_interval") is not None:
                        current_interval_ms = data.get("capture_interval") * 1000
                        logger.info(f"Updated interval from global config: {data.get('capture_interval')}s")
                    if data.get("activity_monitoring_enabled") is not None:
                        is_activity_monitoring_enabled_by_control = data.get("activity_monitoring_enabled")
                        logger.info(f"Updated activity monitoring from global config: {is_activity_monitoring_enabled_by_control}")
                    if data.get("network_monitoring_enabled") is not None:
                        is_network_monitoring_enabled_by_control = data.get("network_monitoring_enabled")
                        logger.info(f"Updated network monitoring from global config: {is_network_monitoring_enabled_by_control}")
                    if data.get("schedule") is not None:
                        current_schedule = data.get("schedule")
                        logger.info("Updated monitoring schedule from global config")
                    if data.get("live_streaming_enabled") is not None:
                        is_live_streaming_enabled_by_control = data.get("live_streaming_enabled")
                        logger.info(f"Updated live streaming flag from global config: {is_live_streaming_enabled_by_control}")
                    if data.get("keystroke_logging_enabled") is not None:
                        is_keystroke_logging_enabled_by_control = data.get("keystroke_logging_enabled")
                        logger.info(f"Updated keystroke logging flag from global config: {is_keystroke_logging_enabled_by_control}")

                    # 2. Reconcile the actual state with the desired configuration state
                    logger.info("Reconciling agent state with new global configuration...")

                    # Check live streaming state
                    is_task_running = live_streaming_task and not live_streaming_task.done()
                    if is_live_streaming_enabled_by_control:
                        if not is_task_running:
                            logger.info("Config requires live stream ON, starting...")
                            asyncio.create_task(start_live_streaming())
                        else:
                            logger.info("Live stream correctly running as per config")
                    else: # Config wants streaming to be OFF
                        if is_task_running:
                            logger.info("Config requires live stream OFF, stopping...")
                            asyncio.create_task(stop_live_streaming())
                        else:
                            logger.info("Live stream correctly stopped as per config")

                    # 3. Save the new config and respond
                    save_local_config()
                    await send_control_response(True, "Global config updated and agent state reconciled.")

                # --- Handler for a manual config refresh command ---
                elif action == "refresh_config":
                    logger.info("Received command to refresh configuration from server")
                    await fetch_config() # fetch_config should also trigger reconciliation

                    # Immediately check break status after config refresh
                    current_break_status = check_break_status()
                    current_time = datetime.now().strftime('%H:%M:%S')
                    logger.info(f"After config refresh at {current_time}: Break status = {current_break_status}")

                    await send_control_response(True, f"Configuration refreshed from server. Break status: {'ON BREAK' if current_break_status else 'WORKING'}")

                else:
                    await send_control_response(False, f"Unknown control command or bundle: Action='{action}', Bundle='{feature_bundle}'")

            # --- Exception Handling for the WebSocket connection ---
            except websockets.exceptions.ConnectionClosedOK:
                print("INFO: Control websocket connection closed gracefully.")
                websocket_client = None
                break # Exit the message handler loop
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"ERROR: Control websocket connection closed with an error: {e}. Will attempt to reconnect.")
                websocket_client = None
                break # Exit the message handler loop
            except json.JSONDecodeError:
                print(f"WARNING: Received non-JSON message from control socket: {message}")
            except Exception as e:
                print(f"ERROR: An unexpected error occurred in the websocket message handler: {e}")
                # Depending on the error, you might want to break or continue
                await asyncio.sleep(1)
        else:
            # If the client is not connected, wait a second before checking again
            await asyncio.sleep(1)

async def send_heartbeat():
    """
    Captures all monitored data, assembles it into a single payload,
    sends it to the backend, and resets counters for the next interval.
    """
    global key_stroke_count, mouse_event_count, typed_keys_string, last_upload_bytes, last_download_bytes, websocket_client, \
           is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, \
           current_interval_ms, is_agent_active_by_schedule

    # Check break status first
    is_break_active = check_break_status()
    is_agent_active_by_schedule = is_within_active_schedule()

    # Add detailed logging for break status
    current_time = datetime.now().strftime('%H:%M:%S')
    logger.debug(f"Heartbeat check at {current_time}: Break={is_break_active}, Schedule={is_agent_active_by_schedule}")

    # Always reset counters regardless of status
    key_stroke_count = 0
    mouse_event_count = 0
    typed_keys_string = ""

    if not is_agent_active_by_schedule:
        logger.info(f"Agent outside active schedule. Current time: {current_time}")
        # Still send heartbeat to report status, but with minimal data
        data = {
            "type": "heartbeat",
            "agent_id": AGENT_ID,
            "window_title": None,
            "active_browser_url": None,
            "screenshot": None,
            "keystroke_count": 0,
            "mouse_event_count": 0,
            "typed_keys": "",
            "upload_bytes": 0,
            "download_bytes": 0,
            "network_type": None,
            "is_recording": False,
            "is_activity_monitoring_enabled": is_activity_monitoring_enabled_by_control,
            "is_network_monitoring_enabled": is_network_monitoring_enabled_by_control,
            "is_live_streaming_enabled": is_live_streaming_enabled_by_control,
            "is_keystroke_logging_enabled": is_keystroke_logging_enabled_by_control,
            "productive_status": "Outside Schedule",
            "current_interval_seconds": current_interval_ms / 1000,
            "is_agent_active_by_schedule": is_agent_active_by_schedule,
            "is_on_break": is_on_break,
            "is_user_on_leave": is_user_on_leave
        }
        try:
            if websocket_client and websocket_client.state == State.OPEN:
                await websocket_client.send(json.dumps(data))
        except Exception as e:
            logger.error(f"Error sending schedule status: {e}")
        return

    if is_break_active:
        logger.info(f"Agent on break - sending break status at {current_time}")
        # Send heartbeat to report break status but with no monitoring data
        data = {
            "type": "heartbeat",
            "agent_id": AGENT_ID,
            "window_title": None,
            "active_browser_url": None,
            "screenshot": None,
            "keystroke_count": 0,
            "mouse_event_count": 0,
            "typed_keys": "",
            "upload_bytes": 0,
            "download_bytes": 0,
            "network_type": None,
            "is_recording": False,
            "is_activity_monitoring_enabled": is_activity_monitoring_enabled_by_control,
            "is_network_monitoring_enabled": is_network_monitoring_enabled_by_control,
            "is_live_streaming_enabled": is_live_streaming_enabled_by_control,
            "is_keystroke_logging_enabled": is_keystroke_logging_enabled_by_control,
            "productive_status": "On Break",
            "current_interval_seconds": current_interval_ms / 1000,
            "is_agent_active_by_schedule": is_agent_active_by_schedule,
            "is_on_break": is_on_break,
            "is_user_on_leave": is_user_on_leave
        }
        try:
            if websocket_client and websocket_client.state == State.OPEN:
                await websocket_client.send(json.dumps(data))
        except Exception as e:
            logger.error(f"Error sending break status: {e}")
        return

    # Normal monitoring when not on break and within schedule
    is_activity_monitoring_effective = is_activity_monitoring_enabled_by_control
    is_network_monitoring_effective = is_network_monitoring_enabled_by_control

    app_name, website_url, network_type = None, None, None
    screenshot_base64 = None
    upload_delta, download_delta = 0, 0
    productive_status = "N/A"

    if is_activity_monitoring_effective:
        combined_events = key_stroke_count + mouse_event_count
        productive_status = "Productive" if combined_events >= PRODUCTIVITY_THRESHOLD_HIGH else \
                            "Neutral" if combined_events >= PRODUCTIVITY_THRESHOLD_LOW else "Idle"

        app_name, website_url = get_active_window_info()

        # Always capture screenshots during active monitoring, even when recording
        screenshot_base64 = capture_screenshot_base64()

    if is_network_monitoring_effective:
        current_net = get_total_bandwidth_usage()
        current_upload, current_download = current_net.bytes_sent, current_net.bytes_recv
        upload_delta = current_upload - last_upload_bytes
        download_delta = current_download - last_download_bytes
        last_upload_bytes = current_upload
        last_download_bytes = current_download

        network_type = get_network_type()

    data = {
        "type": "heartbeat",
        "agent_id": AGENT_ID,
        "window_title": app_name,
        "active_browser_url": website_url,
        "screenshot": screenshot_base64,
        "keystroke_count": key_stroke_count,
        "mouse_event_count": mouse_event_count,
        "typed_keys": typed_keys_string,
        "upload_bytes": upload_delta,
        "download_bytes": download_delta,
        "network_type": network_type,
        "is_recording": is_recording,
        "is_activity_monitoring_enabled": is_activity_monitoring_enabled_by_control,
        "is_network_monitoring_enabled": is_network_monitoring_enabled_by_control,
        "is_live_streaming_enabled": is_live_streaming_enabled_by_control,
        "is_keystroke_logging_enabled": is_keystroke_logging_enabled_by_control,
        "productive_status": productive_status,
        "current_interval_seconds": current_interval_ms / 1000,
        "is_agent_active_by_schedule": is_agent_active_by_schedule,
        "is_on_break": is_on_break,
        "is_user_on_leave": is_user_on_leave
    }

    try:
        if not websocket_client or websocket_client.state != State.OPEN:
             logger.warning("WebSocket not connected. Cannot send heartbeat.")
             return
        await websocket_client.send(json.dumps(data))
    except websockets.exceptions.WebSocketException as wse:
        logger.error(f"WebSocket send failed: {wse}. State: {websocket_client.state if websocket_client else 'Closed'}")
        websocket_client = None
    except Exception as e:
        logger.error(f"Error sending data: {e}")

async def send_keystroke_logs():
    """Send captured keystroke logs to the server."""
    global key_log_buffer, websocket_client

    if not is_keystroke_logging_enabled_by_control:
        if key_log_buffer:
            key_log_buffer = {}  # Clear buffer when logging is disabled
        return

    if not key_log_buffer:
        logger.debug("No keystroke logs to send (buffer empty)")
        return

    logger.info(f"Sending keystroke logs for {len(key_log_buffer)} sources")

    try:
        for source_id, log_data in key_log_buffer.items():
            if log_data['keys']:  # Only send if there are actual keystrokes
                key_sequence = ''.join(log_data['keys'])

                keylog_message = {
                    "type": "key_log",
                    "agent_id": AGENT_ID,
                    "source_app": source_id,
                    "key_sequence": key_sequence,
                    "is_messaging": log_data['is_messaging']
                }

                print(f"DEBUG: Sending keylog message: {json.dumps(keylog_message)[:200]}...")
                await websocket_client.send(json.dumps(keylog_message))
                print(f"✅ Sent keystroke log for {source_id}: {len(key_sequence)} characters")
            else:
                print(f"DEBUG: Skipping {source_id} - no keys to send")

        # Clear the buffer after sending
        key_log_buffer = {}
        print("DEBUG: Keystroke buffer cleared")

    except Exception as e:
        print(f"❌ Error sending keystroke logs: {e}")
        import traceback
        traceback.print_exc()

async def fetch_config():
    """Fetch configuration from the server."""
    global current_interval_ms, is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control
    global is_live_streaming_enabled_by_control, is_keystroke_logging_enabled_by_control, current_schedule

    try:
        headers = {
            'X-AGENT-ID': AGENT_ID,
            'Authorization': f'Bearer {API_KEY}',
            'Content-Type': 'application/json'
        }
        config_url = f"{BACKEND_URL}/monitor/api/config/"
        logger.info(f"Fetching config from: {config_url}")
        async with aiohttp.ClientSession() as session:
            async with session.get(config_url, headers=headers) as response:
                if response.status == 200:
                    config_data = await response.json()
                    logger.info("Config fetched successfully")
                    # Update agent configuration
                    agent_config = config_data.get('agent_config', {})
                    if agent_config:
                        current_interval_ms = agent_config.get('capture_interval_seconds', 10) * 1000
                        is_activity_monitoring_enabled_by_control = agent_config.get('is_activity_monitoring_enabled', True)
                        is_network_monitoring_enabled_by_control = agent_config.get('is_network_monitoring_enabled', True)
                        is_live_streaming_enabled_by_control = agent_config.get('is_live_streaming_enabled', False)
                        is_keystroke_logging_enabled_by_control = agent_config.get('is_keystroke_logging_enabled', False)
                        current_schedule = agent_config.get('schedule', current_schedule)
                        logger.info(f"Updated agent configuration: Interval - {current_interval_ms // 1000}s, "
                                    f"Activity Monitoring - {is_activity_monitoring_enabled_by_control}, "
                                    f"Network Monitoring - {is_network_monitoring_enabled_by_control}")

                    # Update break schedules
                    update_break_schedules(config_data)

                    return config_data
                else:
                    logger.error(f"Error fetching config: {response.status} - {await response.text()}")
                    return None
    except Exception as e:
        logger.error(f"Error fetching config from server: {e}")
        return None

def load_local_config():
    """Load settings from local file when server is unavailable"""
    global current_interval_ms, is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, current_schedule, is_live_streaming_enabled_by_control, is_keystroke_logging_enabled_by_control
    global company_breaks, user_break_schedule, is_user_on_leave

    try:
        config_file_path = "local_agent_config.json"
        if getattr(sys, 'frozen', False):
            config_file_path = os.path.join(os.path.dirname(sys.executable), "local_agent_config.json")

        if os.path.exists(config_file_path):
            with open(config_file_path, 'r') as f:
                local_config = json.load(f)

            current_interval_ms = local_config.get("capture_interval_seconds", 10) * 1000
            is_activity_monitoring_enabled_by_control = local_config.get("is_activity_monitoring_enabled", True)
            is_network_monitoring_enabled_by_control = local_config.get("is_network_monitoring_enabled", True)
            is_live_streaming_enabled_by_control = local_config.get("is_live_streaming_enabled", False)
            is_keystroke_logging_enabled_by_control = local_config.get("is_keystroke_logging_enabled", False)
            current_schedule = local_config.get("schedule", current_schedule)

            # Load break schedules
            company_breaks = local_config.get("company_breaks", [])
            user_break_schedule = local_config.get("user_break_schedule", [])
            is_user_on_leave = local_config.get("is_user_on_leave", False)

            last_updated = local_config.get("last_updated", 0)
            print(f"Loaded local config (last updated: {datetime.fromtimestamp(last_updated)})")
            print(f"Interval: {current_interval_ms//1000}s, Activity: {is_activity_monitoring_enabled_by_control}, Network: {is_network_monitoring_enabled_by_control}")
            print(f"Break schedules loaded - Company: {len(company_breaks)}, User: {len(user_break_schedule)}, On leave: {is_user_on_leave}")
        else:
            print("No local config found, using defaults")
    except Exception as e:
        print(f"Error loading local config: {e}")


def save_local_config():
    """Save current settings to local file for offline use"""
    try:
        local_config = {
            "capture_interval_seconds": current_interval_ms // 1000,
            "is_activity_monitoring_enabled": is_activity_monitoring_enabled_by_control,
            "is_network_monitoring_enabled": is_network_monitoring_enabled_by_control,
            "is_live_streaming_enabled": is_live_streaming_enabled_by_control,
            "is_keystroke_logging_enabled": is_keystroke_logging_enabled_by_control,
            "schedule": current_schedule,
            "company_breaks": company_breaks,
            "user_break_schedule": user_break_schedule,
            "is_user_on_leave": is_user_on_leave,
            "last_updated": time.time()
        }

        config_file_path = "local_agent_config.json"
        if getattr(sys, 'frozen', False):
            config_file_path = os.path.join(os.path.dirname(sys.executable), "local_agent_config.json")

        with open(config_file_path, 'w') as f:
            json.dump(local_config, f, indent=2, default=str)  # default=str to handle time objects
        print(f"Config saved locally to {config_file_path}")
    except Exception as e:
        print(f"Error saving local config: {e}")

async def run_monitoring_loop(config, agent_id):
    """
    The main operational loop for an already-paired and registered agent.
    """
    global websocket_client, AGENT_ID, BACKEND_URL, API_KEY

    AGENT_ID = agent_id
    BACKEND_URL = config['base_url']
    API_KEY = config['api_key']

    base_ws_url = config['base_url'].replace('http', 'ws', 1)
    websocket_url = f"{base_ws_url}/monitor/ws/agent/{agent_id}/"

    api_key = config['api_key']

    print(f"--- Monitoring Mode for Agent: {agent_id} ---")
    print(f"Attempting to connect to: {websocket_url}")

    # Load local config first, fetch from server after WebSocket auth
    load_local_config()

    # Schedule periodic config refresh every 5 minutes
    last_config_fetch = 0  # Force initial fetch after auth
    CONFIG_REFRESH_INTERVAL = 300  # 5 minutes

    print(f"--- Monitoring Mode for Agent ID: {agent_id} ---")

    while True:
        try:
            async with websockets.connect(websocket_url) as websocket:
                websocket_client = websocket
                print(f"Connected to {websocket_url}. Authenticating...")

                auth_payload = {"type": "auth", "api_key": api_key}
                await websocket.send(json.dumps(auth_payload))

                print("Authentication successful. Starting data submission loop.")

                # Fetch initial config after successful authentication
                logger.info("Fetching initial configuration from server...")
                await fetch_config()
                last_config_fetch = time.time()

                message_handler_task = asyncio.create_task(websocket_message_handler())

                while True:
                    # Check if WebSocket is still connected before proceeding
                    if not websocket_client or websocket_client.state != State.OPEN:
                        logger.warning("WebSocket connection lost during monitoring loop, will reconnect")
                        # Cancel the message handler task before breaking
                        if not message_handler_task.done():
                            message_handler_task.cancel()
                            try:
                                await message_handler_task
                            except asyncio.CancelledError:
                                pass
                        break

                    current_time = time.time()
                    if current_time - last_config_fetch > CONFIG_REFRESH_INTERVAL:
                        print("Refreshing configuration from server...")
                        print(f"DEBUG: Keystroke logging flag BEFORE refresh: {is_keystroke_logging_enabled_by_control}")
                        await fetch_config()
                        print(f"DEBUG: Keystroke logging flag AFTER refresh: {is_keystroke_logging_enabled_by_control}")
                        last_config_fetch = current_time
                    
                    try:
                        await send_heartbeat()
                        await send_keystroke_logs()
                    except Exception as e:
                        logger.error(f"Error sending data, connection may be lost: {e}")
                        websocket_client = None
                        break

                    interval_seconds = current_interval_ms / 1000
                    await asyncio.sleep(interval_seconds)

                # Cleanup message handler task
                if not message_handler_task.done():
                    message_handler_task.cancel()
                    try:
                        await message_handler_task
                    except asyncio.CancelledError:
                        pass

        except websockets.exceptions.ConnectionClosed as e:
            logger.warning(f"WebSocket connection closed (Code: {e.code}). Retrying in 15s...")
            websocket_client = None
        except websockets.exceptions.InvalidStatusCode as e:
            logger.error(f"WebSocket connection failed with status {e.status_code}. Retrying in 15s...")
            websocket_client = None
        except websockets.exceptions.WebSocketException as e:
            logger.error(f"WebSocket error: {e}. Retrying in 15s...")
            websocket_client = None
        except Exception as e:
            logger.error(f"Unexpected error in monitoring loop: {e}. Retrying in 15s...")
            websocket_client = None

        # Clean up any remaining tasks before reconnecting
        if 'message_handler_task' in locals() and not message_handler_task.done():
            message_handler_task.cancel()
            try:
                await message_handler_task
            except asyncio.CancelledError:
                pass

        await asyncio.sleep(15)

async def main():
    """Orchestrates the agent's startup workflow."""
    os.makedirs(LOCAL_RECORDINGS_TEMP_DIR, exist_ok=True)

    config = load_config()

    agent_id = get_persistent_agent_id()

    if agent_id is None:
        newly_paired_id = await pair_with_server(config)
        if newly_paired_id:
            logger.info("Pairing successful! Agent starting in monitoring mode.")
            await run_monitoring_loop(config, newly_paired_id)
        else:
            logger.error("Pairing failed. Please check the token and network, then restart.")
    else:
        logger.info(f"Agent starting with existing ID: {agent_id}")
        await run_monitoring_loop(config, agent_id)

if __name__ == "__main__":
    print("Initializing Agent...")
    config_data = load_config()
    BACKEND_URL = config_data['base_url']
    API_KEY = config_data['api_key']

    keyboard_listener = keyboard.Listener(on_press=on_key_press)
    mouse_listener = mouse.Listener(on_click=on_click, on_scroll=on_scroll)
    keyboard_listener.start()
    mouse_listener.start()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error(f"Fatal error occurred: {e}")
    finally:
        logger.info("Agent process terminated")
        sys.exit(0)