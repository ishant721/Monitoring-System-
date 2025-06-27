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
import datetime
import tempfile

# Keep all your existing data-gathering imports
import mss
from PIL import Image
import psutil
import pyscreeze
from pynput import keyboard, mouse
from websockets.protocol import State

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
BACKEND_URL = ""
API_KEY = ""
AGENT_ID = ""

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
    key_stroke_count += 1
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
            typed_keys_string += key_str
    except AttributeError:
        key_str = f'[{str(key).replace("Key.", "").upper()}]'

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
    print("--- Agent First-Time Setup: Pairing Mode ---")
    pairing_token = input("Please enter the one-time pairing token from the web dashboard: ").strip()
    if not pairing_token:
        print("Pairing token cannot be empty. Exiting.")
        return None

    new_agent_id = str(uuid.uuid4())
    base_ws_url = config['base_url'].replace('http', 'ws', 1)
    pairing_url = f"{base_ws_url}/monitor/ws/agent/pairing/"

    print(f"Connecting to {pairing_url} to pair with new ID: {new_agent_id}")
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
                return new_agent_id
            else:
                print(f"Pairing Failed: {response.get('reason', 'Unknown error from server')}")
                return None
    except Exception as e:
        print(f"An error occurred during the pairing process: {e}")
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

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
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
                lambda: requests.post(f"{BACKEND_URL}/monitor/api/upload_recording/", files=files, data=data, headers=headers, timeout=600)
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

    now_local = datetime.datetime.now()
    today_weekday_str = now_local.strftime('%A').lower()

    day_schedule = current_schedule.get(today_weekday_str, {"start": None, "end": None})

    start_time_str = day_schedule.get("start")
    end_time_str = day_schedule.get("end")

    if not start_time_str or not end_time_str:
        return True

    try:
        start_time = datetime.datetime.strptime(start_time_str, "%H:%M").time()
        end_time = datetime.datetime.strptime(end_time_str, "%H:%M").time()

        current_time = now_local.time()

        if start_time <= end_time:
            return start_time <= current_time <= end_time
        else:
            return current_time >= start_time or current_time <= end_time

    except (ValueError, TypeError) as e:
        print(f"Warning: Invalid time format in schedule for {today_weekday_str} ('{start_time_str}'-'{end_time_str}'). Error: {e}")
        return True

async def websocket_message_handler():
    global websocket_client, is_recording, ffmpeg_process, recording_task, \
           is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, \
           current_interval_ms, current_schedule

    while True:
        if websocket_client and websocket_client.state == State.OPEN:
            try:
                message = await websocket_client.recv()
                data = json.loads(message)

                if data.get("type") == "control":
                    action = data.get("action")
                    feature_bundle = data.get("feature_bundle")
                    new_interval_from_control = data.get("interval")

                    print(f"Received control command: action='{action}', feature_bundle='{feature_bundle}', interval='{new_interval_from_control}'")

                    if feature_bundle == "screen_recording":
                        if action == "start":
                            if not is_recording:
                                await start_recording()
                            else:
                                await send_control_response(False, "Recording already active.")
                        elif action == "stop":
                            if is_recording:
                                await stop_recording()
                            else:
                                await send_control_response(False, "No recording active.")
                        else:
                            await send_control_response(False, f"Unknown action '{action}' for screen_recording.")

                    elif feature_bundle == "activity_monitoring":
                        if action == "enable":
                            is_activity_monitoring_enabled_by_control = True
                            print("Command: Activity Monitoring Enabled.")
                            await send_control_response(True, "Activity monitoring enabled.")
                        elif action == "disable":
                            is_activity_monitoring_enabled_by_control = False
                            print("Command: Activity Monitoring Disabled.")
                            await send_control_response(True, "Activity monitoring disabled.")
                        else:
                            await send_control_response(False, f"Unknown action '{action}' for activity_monitoring.")

                    elif feature_bundle == "network_monitoring":
                        if action == "enable":
                            is_network_monitoring_enabled_by_control = True
                            print("Command: Network Monitoring Enabled.")
                            await send_control_response(True, "Network monitoring enabled.")
                        elif action == "disable":
                            is_network_monitoring_enabled_by_control = False
                            print("Command: Network Monitoring Disabled.")
                            await send_control_response(True, "Network monitoring disabled.")
                        else:
                            await send_control_response(False, f"Unknown action '{action}' for network_monitoring.")

                    elif feature_bundle == "interval_control":
                        if action == "set" and new_interval_from_control is not None and new_interval_from_control > 0:
                            current_interval_ms = new_interval_from_control * 1000
                            print(f"Command: Set interval to {new_interval_from_control} seconds from direct control.")
                            await send_control_response(True, f"Interval set to {new_interval_from_control} seconds.")
                        else:
                            await send_control_response(False, "Invalid interval control command.")

                    elif action == "set_global_config":
                        print(f"Received global config update via broadcast: {data}")
                        if data.get("capture_interval") is not None:
                            current_interval_ms = data.get("capture_interval") * 1000
                            print(f"Updated interval from global config: {current_interval_ms / 1000}s")
                        if data.get("activity_monitoring_enabled") is not None:
                            is_activity_monitoring_enabled_by_control = data.get("activity_monitoring_enabled")
                            print(f"Updated activity monitoring from global config: {is_activity_monitoring_enabled_by_control}")
                        if data.get("network_monitoring_enabled") is not None:
                            is_network_monitoring_enabled_by_control = data.get("network_monitoring_enabled")
                            print(f"Updated network monitoring from global config: {is_network_monitoring_enabled_by_control}")
                        if data.get("schedule") is not None:
                            current_schedule = data.get("schedule")
                            print(f"Updated monitoring schedule from global config: {current_schedule}")

                        await send_control_response(True, "Global config updated.")

                    else:
                        await send_control_response(False, f"Unknown control command: Type={data.get('type')}, Bundle={feature_bundle}, Action={action}")

            except websockets.exceptions.ConnectionClosedOK:
                print("WebSocket receive loop closed gracefully.")
                websocket_client = None
                break
            except websockets.exceptions.WebSocketException as e:
                print(f"WebSocket receive error: {e}. Attempting reconnect on next heartbeat.")
                websocket_client = None
                break
            except json.JSONDecodeError:
                print(f"Received non-JSON message: {message}")
            except Exception as e:
                print(f"Error processing WebSocket message: {e}")
        else:
            await asyncio.sleep(1)

async def send_heartbeat():
    """
    Captures all monitored data, assembles it into a single payload,
    sends it to the backend, and resets counters for the next interval.
    """
    global key_stroke_count, mouse_event_count, typed_keys_string, last_upload_bytes, last_download_bytes, websocket_client, \
           is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, \
           current_interval_ms, is_agent_active_by_schedule

    is_agent_active_by_schedule = is_within_active_schedule()

    if not is_agent_active_by_schedule:
        print(f"Agent is outside of active schedule. Skipping data capture. Current UTC: {datetime.datetime.utcnow().strftime('%H:%M:%S')}")
        key_stroke_count = 0
        mouse_event_count = 0
        typed_keys_string = ""
        return

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

        if not is_recording:
            screenshot_base64 = capture_screenshot_base64()
    else:
        key_stroke_count = 0
        mouse_event_count = 0
        typed_keys_string = ""

    if is_network_monitoring_effective:
        current_net = get_total_bandwidth_usage()
        current_upload, current_download = current_net.bytes_sent, current_net.bytes_recv
        upload_delta = current_upload - last_upload_bytes
        download_delta = current_download - last_download_bytes
        last_upload_bytes = current_upload
        last_download_bytes = current_download

        network_type = get_network_type()
    else:
        upload_delta, download_delta = 0, 0

    print(f"Sending data: App='{app_name}' | Keys={key_stroke_count} | Mouse={mouse_event_count} | Typed='{typed_keys_string[:30]}...' | Up={upload_delta} | Down={download_delta} | SS Sent={'Yes' if screenshot_base64 else 'No'}")

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
        "productive_status": productive_status,
        "current_interval_seconds": current_interval_ms / 1000,
        "is_agent_active_by_schedule": is_agent_active_by_schedule
    }

    try:
        if not websocket_client or websocket_client.state != State.OPEN:
             print("WebSocket not connected. Cannot send heartbeat.")
             return
        await websocket_client.send(json.dumps(data))
    except websockets.exceptions.WebSocketException as wse:
        print(f"WebSocket send failed: {wse}. State: {websocket_client.state if websocket_client else 'Closed'}.")
        websocket_client = None
    except Exception as e:
        print(f"Error sending data: {e}")

    key_stroke_count = 0
    mouse_event_count = 0
    typed_keys_string = ""

async def fetch_config():
    global current_interval_ms, is_activity_monitoring_enabled_by_control, is_network_monitoring_enabled_by_control, current_schedule

    try:
        headers = {"X-API-KEY": API_KEY}
        response = requests.get(f"{BACKEND_URL}/api/config/", headers=headers, timeout=5)
        response.raise_for_status()
        config_data = response.json()

        new_interval_s = config_data.get("capture_interval", 10)
        current_interval_ms = new_interval_s * 1000

        is_activity_monitoring_enabled_by_control = config_data.get("activity_monitoring_enabled", True)
        is_network_monitoring_enabled_by_control = config_data.get("network_monitoring_enabled", True)
        current_schedule = config_data.get("schedule", current_schedule)

        print(f"Fetched config: Interval {new_interval_s} seconds.")
        print(f"Activity Monitoring Enabled: {is_activity_monitoring_enabled_by_control}")
        print(f"Network Monitoring Enabled: {is_network_monitoring_enabled_by_control}")
        print(f"Monitoring Schedule: {current_schedule}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching config, will use defaults. Error: {e}")
    except Exception as e:
        print(f"General error fetching config: {e}")

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

    await fetch_config()

    print(f"--- Monitoring Mode for Agent ID: {agent_id} ---")

    while True:
        try:
            async with websockets.connect(websocket_url) as websocket:
                websocket_client = websocket
                print(f"Connected to {websocket_url}. Authenticating...")

                auth_payload = {"type": "auth", "api_key": api_key}
                await websocket.send(json.dumps(auth_payload))

                print("Authentication successful. Starting data submission loop.")

                message_handler_task = asyncio.create_task(websocket_message_handler())

                while True:
                    await send_heartbeat()

                    interval_seconds = current_interval_ms / 1000
                    await asyncio.sleep(interval_seconds)

        except websockets.exceptions.ConnectionClosed as e:
            print(f"Connection closed (Code: {e.code}). Retrying in 15s...")
            websocket_client = None
        except Exception as e:
            print(f"An unexpected error occurred in monitoring loop: {e}. Retrying in 15s...")
            websocket_client = None

        await asyncio.sleep(15)

async def main():
    """Orchestrates the agent's startup workflow."""
    os.makedirs(LOCAL_RECORDINGS_TEMP_DIR, exist_ok=True)

    config = load_config()

    agent_id = get_persistent_agent_id()

    if agent_id is None:
        newly_paired_id = await pair_with_server(config)
        if newly_paired_id:
            print("\nPairing successful! Agent will now start in monitoring mode.")
            await run_monitoring_loop(config, newly_paired_id)
        else:
            print("\nPairing failed. Please check the token and network, then restart.")
    else:
        await run_monitoring_loop(config, agent_id)

if __name__ == "__main__":
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
        print("\nAgent stopped by user.")
    except Exception as e:
        print(f"A fatal error occurred: {e}")
    finally:
        print("Agent process terminated.")
        sys.exit(0)