import os
import re
import subprocess
from scapy.all import rdpcap, TCP, Raw

PCAP_FILE = "security-footage-1648933966395.pcap"
BOUNDARY = b"--BoundaryString"
FRAME_PREFIX = "frame_"
FRAME_FOLDER = "frames"
OUTPUT_VIDEO = "output_video.mp4"
FPS = 10

def extract_mjpeg_stream(pcap_file):
    packets = rdpcap(pcap_file)
    tcp_data = b""

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp_data += bytes(pkt[Raw].load)

    return tcp_data

def extract_frames(buffer, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    frame_count = 0
    offset = 0

    while True:
        start = buffer.find(BOUNDARY, offset)
        if start == -1:
            break
        end = buffer.find(BOUNDARY, start + len(BOUNDARY))
        if end == -1:
            break

        part = buffer[start:end]
        match = re.search(b"Content-Length:\s*(\d+)", part)
        if not match:
            offset = end
            continue

        content_length = int(match.group(1))
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            offset = end
            continue

        jpeg_start = start + header_end + 4
        jpeg_end = jpeg_start + content_length
        jpeg_data = buffer[jpeg_start:jpeg_end]

        frame_name = os.path.join(output_dir, f"{FRAME_PREFIX}{frame_count:04d}.jpg")
        with open(frame_name, "wb") as f:
            f.write(jpeg_data)

        print(f"Saved frame {frame_count}")
        frame_count += 1
        offset = end

    return frame_count

def create_video(frame_dir, fps, output_file):
    cmd = [
        "ffmpeg",
        "-y",
        "-framerate", str(fps),
        "-i", os.path.join(frame_dir, f"{FRAME_PREFIX}%04d.jpg"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        output_file
    ]
    try:
        subprocess.run(cmd, check=True)
        print(f"🎞️ Video created successfully: {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"❌ FFmpeg failed: {e}")

def main():
    print("🔍 Parsing PCAP and extracting MJPEG stream...")
    buffer = extract_mjpeg_stream(PCAP_FILE)

    print("🖼️ Extracting JPEG frames...")
    frame_count = extract_frames(buffer, FRAME_FOLDER)

    print(f"✅ Extracted {frame_count} frames. Creating video...")
    create_video(FRAME_FOLDER, FPS, OUTPUT_VIDEO)

if __name__ == "__main__":
    main()
