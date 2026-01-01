# Parti VOD Downloader (WIP)

<img width="1135" height="986" alt="image" src="https://github.com/user-attachments/assets/2e179fed-4299-44a2-810b-22e7525171d6" />

A Tkinter GUI tool to download Parti VODs by resolving a Parti page URL (e.g. `https://parti.com/video/<id>`) into the actual HLS playlists on `media.parti.com`, then downloading segments and merging them into an MP4.

## Features

- Paste **Parti page URL** or direct **.m3u8**
- Auto-detects:
  - `main.m3u8` / `master.m3u8` (normal)
  - `index-1.m3u8` (best)
 <img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/6492ef82-07ee-4069-941d-9b160a7f6f0e" />
<img width="1745" height="700" alt="image" src="https://github.com/user-attachments/assets/db03215c-768f-4802-933b-0d7e162b32df" />

- **Playlist Source selector**
  - Best (index-1)
  - Normal (main/master)
- **Quality dropdown** (only for Normal mode when a master playlist exposes variants)
- Multithreaded segment download
- Merge to MP4 using `ffmpeg`
- Cancel download at any time (also stops ffmpeg merge)
- Optional: keep segments folder for debugging

<img width="377" height="516" alt="image" src="https://github.com/user-attachments/assets/bb70f0c3-1ca7-4db6-a44d-30fcfe8deeb9" />

> Note: This is provided for personal/educational use. Respect content rights and platform rules.

## Requirements

- Python 3.10+ recommended
- `ffmpeg` installed and available in PATH
- Playwright browser installed

## Install


```bash
git clone [parti-vod-downloader](https://github.com/dismissed8582/parti-vod-downloader.git)
cd parti-vod-downloader
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python -m playwright install
```
After doing those steps, do those steps in the Terminal:

<img width="701" height="297" alt="image" src="https://github.com/user-attachments/assets/edd59284-467e-4d6f-a0f2-0f690b48f8d4" />

Probably gonna release the finished application for everyone to use.
