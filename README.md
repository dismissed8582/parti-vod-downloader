# Parti VOD Downloader

A Tkinter GUI tool to download Parti VODs by resolving a Parti page URL (e.g. `https://parti.com/video/<id>`) into the actual HLS playlists on `media.parti.com`, then downloading segments and merging them into an MP4.

## Features

- Paste **Parti page URL** or direct **.m3u8**
- Auto-detects:
  - `main.m3u8` / `master.m3u8` (normal)
  - `index-1.m3u8` (best)
- **Playlist Source selector**
  - Best (index-1)
  - Normal (main/master)
- **Quality dropdown** (only for Normal mode when a master playlist exposes variants)
- Multithreaded segment download
- Merge to MP4 using `ffmpeg`
- Cancel download at any time (also stops ffmpeg merge)
- Optional: keep segments folder for debugging

> Note: This is provided for personal/educational use. Respect content rights and platform rules.

## Requirements

- Python 3.10+ recommended
- `ffmpeg` installed and available in PATH
- Playwright browser installed

## Install

```bash
git clone parti-vod-downloader
cd parti-vod-downloader
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python -m playwright install
