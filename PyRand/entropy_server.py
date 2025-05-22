#!/usr/bin/env python3
"""
Enhanced Entropy Server for Silent App

This server provides high-quality entropy from multiple sources including:
- Video frame analysis
- System hardware sensors
- Timing measurements
- Environmental noise

It serves entropy through a secure API endpoint with rate limiting and authentication.
"""

import cv2
import numpy as np
import os
import hashlib
import random
import time
import uuid
import threading
import queue
import logging
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("entropy_server.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("entropy_server")

# Configuration
VIDEO_DIR = "../Videos"  # Use local directory instead of parent directory
ENTROPY_POOL_SIZE = 1024 * 1024  # 1MB entropy pool
REFRESH_INTERVAL = 300  # Refresh entropy pool every 5 minutes
API_KEYS = {
    "silent_client_dev": "development-only-key",
    # Add production keys here
}

# Find available video files
video_extensions = ['.mp4', '.avi', '.mov', '.mkv', '.webm', '.wmv', '.flv', '.m4v']
VIDEO_FILES = []

# Dynamically find video files if they exist
if os.path.exists(VIDEO_DIR):
    for file in os.listdir(VIDEO_DIR):
        if any(file.lower().endswith(ext) for ext in video_extensions):
            VIDEO_FILES.append(os.path.join(VIDEO_DIR, file))
    logger.info(f"Found {len(VIDEO_FILES)} video files: {[os.path.basename(v) for v in VIDEO_FILES]}")
else:
    logger.warning(f"Video directory {VIDEO_DIR} not found. Will use system entropy only.")
    
FRAME_SKIP_RANGES = [(30, 50), (40, 60), (20, 40)]  # Random frame skipping for efficiency
MAX_PIXELS = 15000  # Maximum pixels to sample per frame

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global entropy pool
entropy_pool = bytearray()
last_refresh_time = 0
entropy_lock = threading.Lock()
entropy_queue = queue.Queue(maxsize=10)  # Buffer for background processing
refresh_in_progress = threading.Event()  # Flag to track if a refresh is in progress

# Rate limiting
request_counters = {}  # IP address -> (count, first_request_time)
RATE_LIMIT = 100  # requests per hour
RATE_WINDOW = 3600  # 1 hour in seconds

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key in API_KEYS.values():
            return f(*args, **kwargs)
        else:
            abort(401)  # Unauthorized
    return decorated_function

def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()

        # Initialize or reset if window expired
        if ip not in request_counters or now - request_counters[ip][1] > RATE_WINDOW:
            request_counters[ip] = (1, now)
            return f(*args, **kwargs)

        count, start_time = request_counters[ip]

        # Check if rate limit exceeded
        if count >= RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for IP: {ip}")
            abort(429)  # Too Many Requests

        # Increment counter
        request_counters[ip] = (count + 1, start_time)
        return f(*args, **kwargs)
    return decorated_function

def compute_hash(data, algorithm="sha256"):
    """Generates a cryptographic hash from the given data."""
    if algorithm == "sha256":
        return hashlib.sha256(data).digest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).digest()
    else:
        return hashlib.sha256(data).digest()

def process_frame(frame):
    """Extracts random pixels from the frame for entropy."""
    if frame is None or frame.size == 0:
        return []

    try:
        # Process frame using optimal numpy operations
        y, x, _ = frame.shape
        # Safely handle cases where y*x < MAX_PIXELS
        sample_size = min(MAX_PIXELS, y * x)
        indices = np.random.choice(y * x, sample_size, replace=False)
        sampled_pixels = frame.reshape(-1, 3)[indices]
        return sampled_pixels.flatten().tolist()
    except Exception as e:
        logger.error(f"Error processing frame: {str(e)}")
        return []

def process_video(video_path, frame_skip):
    """Extracts entropy from the video using a specified frame skip interval."""
    # Check if video file exists
    if not os.path.exists(video_path):
        logger.warning(f"Video file {video_path} not found. Using fallback entropy.")
        # Generate fallback entropy if video is missing
        return os.urandom(1024 * 10)  # 10KB of random data as fallback

    cap = None
    try:
        start_time = time.time()
        max_time = 10  # REDUCED from 15 to 10 seconds per video for faster processing
        
        logger.info(f"Opening video file: {video_path}")
        cap = cv2.VideoCapture(video_path)
        entropy_data = []

        # Check if video was opened successfully
        if not cap.isOpened():
            logger.warning(f"Could not open video {video_path}. Using fallback entropy.")
            return os.urandom(1024 * 10)
            
        # Get some video info for logging
        frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # For small videos, process fewer frames
        if frame_count < 1000:
            max_frames = min(frame_count, 30)  # REDUCED from 50 to 30 for faster processing
        else:
            max_frames = min(frame_count, 50)  # REDUCED from 75 to 50 for faster processing
            
        frames_processed = 0
        
        logger.info(f"Processing video: {os.path.basename(video_path)} ({frame_count} frames, {fps:.1f} fps, {width}x{height}, limit={max_frames})")

        # Set a watchdog timer to prevent hanging
        watchdog_timer = threading.Timer(max_time + 2, lambda: cap.release() if cap and cap.isOpened() else None)
        watchdog_timer.daemon = True
        watchdog_timer.start()

        # Process video frames with limits
        while frames_processed < max_frames:
            # Check if we've exceeded the time limit
            elapsed_time = time.time() - start_time
            if elapsed_time > max_time:
                logger.warning(f"Time limit reached for {video_path} after {frames_processed} frames")
                break
                
            # Read frame with timeout check
            read_start = time.time()
            ret, frame = cap.read()
            read_time = time.time() - read_start
            
            # If reading a frame takes too long, bail out
            if read_time > 0.3:  # REDUCED from 0.5 to 0.3 second for faster failure detection
                logger.warning(f"Frame read took too long ({read_time:.2f}s), abandoning video processing")
                break
                
            if not ret:
                logger.info(f"Reached end of video after {frames_processed} frames")
                break
                
            # Process this frame if it falls on our sampling interval
            if frames_processed % frame_skip == 0:
                # Extract random information from the frame
                pixel_values = process_frame(frame)
                if pixel_values:
                    # Include some metadata about the frame position - adds more entropy
                    entropy_data.extend(str(frames_processed).encode())
                    entropy_data.extend(pixel_values)
                    
            frames_processed += 1
            
            # Add a small pause to prevent high CPU usage and potential hanging
            # Only add this pause every N frames
            if frames_processed % 10 == 0:
                time.sleep(0.001)  # 1ms pause every 10 frames
                
        # Cancel the watchdog timer if we completed normally
        watchdog_timer.cancel()
                
        # Log statistics
        elapsed_time = time.time() - start_time
        logger.info(f"Processed {frames_processed} frames from {os.path.basename(video_path)} in {elapsed_time:.2f}s")
        
        if len(entropy_data) == 0:
            logger.warning(f"No entropy collected from {video_path}, using fallback")
            return os.urandom(1024 * 10)
            
        # Convert collected entropy to bytes
        entropy_bytes = bytes(entropy_data)
        
        # Hash the output to ensure good mixing of the entropy
        if len(entropy_bytes) > 1024 * 10:  # If we have a lot of data, hash chunks
            # Process in chunks for very large files
            chunk_size = 1024 * 10
            num_chunks = len(entropy_bytes) // chunk_size + (1 if len(entropy_bytes) % chunk_size else 0)
            hashed_data = bytearray()
            
            for i in range(num_chunks):
                start_idx = i * chunk_size
                end_idx = min(start_idx + chunk_size, len(entropy_bytes))
                chunk = entropy_bytes[start_idx:end_idx]
                hashed_chunk = hashlib.sha256(chunk).digest()
                hashed_data.extend(hashed_chunk)
                
            return bytes(hashed_data)
        else:
            # Direct hash for smaller amounts of data
            return hashlib.sha256(entropy_bytes).digest() + entropy_bytes[:1024]
            
    except Exception as e:
        logger.error(f"Error processing video {os.path.basename(video_path)}: {str(e)}")
        return os.urandom(1024 * 10)  # Return random data as fallback
    finally:
        # Always make sure to release the video capture
        if cap is not None and cap.isOpened():
            cap.release()
            
        # Try to help with memory cleanup since OpenCV can sometimes leave resources open
        try:
            import gc
            gc.collect()
        except:
            pass

def collect_system_entropy():
    """Collects entropy from system sources."""
    system_entropy = bytearray()

    # Current time at microsecond precision
    time_bytes = str(time.time()).encode()
    system_entropy.extend(time_bytes)

    # Process information
    process_info = f"{os.getpid()}-{os.getppid()}-{time.process_time()}".encode()
    system_entropy.extend(process_info)

    # Random timing measurements
    timing_entropy = bytearray()
    for _ in range(64):
        start = time.perf_counter_ns()
        # Create some variability in execution time
        _ = [random.random() for _ in range(random.randint(10, 100))]
        end = time.perf_counter_ns()
        # Use the least significant byte of timing difference
        timing_entropy.append((end - start) & 0xFF)
    system_entropy.extend(timing_entropy)

    # Filesystem information (file sizes, etc.)
    try:
        for root, _, files in os.walk(".", topdown=True, followlinks=False):
            if len(files) > 0:
                sample_files = random.sample(files, min(5, len(files)))
                for file in sample_files:
                    path = os.path.join(root, file)
                    try:
                        stats = os.stat(path)
                        stat_info = f"{stats.st_size}-{stats.st_mtime}".encode()
                        system_entropy.extend(stat_info)
                    except:
                        pass
                break  # Only process one directory
    except:
        pass

    # OS urandom as a backup
    system_entropy.extend(os.urandom(256))

    return bytes(system_entropy)

def generate_entropy_seed(size=64, extra_entropy=None):
    """
    Generates a seed of specified size using entropy extracted from videos
    and system sources.

    Args:
        size: Size of the seed in bytes
        extra_entropy: Optional additional entropy provided by the client

    Returns:
        Hexadecimal string of the generated seed
    """
    global entropy_pool, last_refresh_time

    with entropy_lock:
        current_time = time.time()

        # Check if we need to refresh the entropy pool
        if len(entropy_pool) < size * 2 or current_time - last_refresh_time > REFRESH_INTERVAL:
            refresh_entropy_pool()

        # Create a seed from the entropy pool
        if len(entropy_pool) >= size:
            # Take bytes from the pool
            seed_bytes = entropy_pool[:size]
            # Remove used bytes from the pool
            entropy_pool = entropy_pool[size:]

            # If extra entropy is provided, mix it in
            if extra_entropy and isinstance(extra_entropy, str):
                try:
                    client_entropy = bytes.fromhex(extra_entropy)
                    # Ensure client_entropy is at least size bytes by repeating if necessary
                    if len(client_entropy) < size:
                        client_entropy = client_entropy * (size // len(client_entropy) + 1)
                    # XOR the first 'size' bytes of client_entropy with seed_bytes
                    seed_bytes = bytes(a ^ b for a, b in zip(seed_bytes, client_entropy[:size]))
                except Exception as e:
                    logger.warning(f"Failed to incorporate client entropy: {str(e)}")

            # Final hash to ensure good statistical properties
            seed = compute_hash(seed_bytes + os.urandom(32), "sha256")[:size]
            return seed.hex()
        else:
            # Emergency fallback
            logger.warning("Entropy pool depleted, using emergency entropy")
            fallback = os.urandom(size)
            seed = compute_hash(fallback, "sha256")[:size]
            return seed.hex()

def refresh_entropy_pool():
    """Rebuilds the entropy pool from video sources and system entropy."""
    global entropy_pool, last_refresh_time

    logger.info("Refreshing entropy pool...")
    start_time = time.time()
    max_refresh_time = 90  # REDUCED from 120 to 90 seconds total refresh time

    try:
        all_entropy = bytearray()

        # 1. Add system entropy first (always works)
        system_entropy = collect_system_entropy()
        all_entropy.extend(system_entropy)
        logger.info(f"Collected {len(system_entropy)} bytes of system entropy")
        
        # Add some initial entropy to the pool immediately
        with entropy_lock:
            initial_entropy = compute_hash(system_entropy + os.urandom(32), "sha512")
            entropy_pool.extend(initial_entropy)
            logger.info(f"Added {len(initial_entropy)} bytes of initial entropy to pool")

        # 2. Process videos for entropy if available
        if VIDEO_FILES:
            # Use all available videos in the directory
            videos_to_process = VIDEO_FILES.copy()
            random.shuffle(videos_to_process)  # Process in random order for better entropy
            
            logger.info(f"Planning to process these videos: {[os.path.basename(v) for v in videos_to_process]}")
            
            # Process each video sequentially
            for i, video in enumerate(videos_to_process):
                # Check if we've exceeded the max refresh time
                elapsed_time = time.time() - start_time
                remaining_time = max_refresh_time - elapsed_time
                if remaining_time <= 0:
                    logger.warning(f"Max refresh time reached ({max_refresh_time}s), skipping remaining videos")
                    break
                    
                frame_skip = random.randint(*FRAME_SKIP_RANGES[i % len(FRAME_SKIP_RANGES)])
                logger.info(f"Processing video {i+1} of {len(videos_to_process)}: {os.path.basename(video)} with frame_skip={frame_skip}...")
                
                try:
                    # Use a separate thread with a timeout to process the video
                    # This ensures a single video can't hang the entire process
                    video_result = [None]  # Use a list to store the result from the thread
                    
                    def process_video_with_timeout():
                        video_result[0] = process_video(video, frame_skip)
                    
                    video_thread = threading.Thread(target=process_video_with_timeout)
                    video_thread.daemon = True
                    video_thread.start()
                    
                    # Set a timeout for this single video processing
                    # Use a shorter timeout for later videos to ensure we can process all videos
                    video_timeout = min(25, remaining_time - 5)  # max 25 seconds per video, with 5 second buffer
                    video_thread.join(timeout=video_timeout)
                    
                    if video_thread.is_alive():
                        logger.warning(f"Video processing thread for {os.path.basename(video)} appears to be hung. Skipping.")
                        video_data = os.urandom(1024 * 10)  # Fallback entropy
                        
                        # Attempt to help with thread cleanup
                        try:
                            import gc
                            gc.collect()
                        except:
                            pass
                    else:
                        video_data = video_result[0] or os.urandom(1024 * 10)
                    
                    all_entropy.extend(video_data)
                    logger.info(f"Collected {len(video_data)} bytes from {os.path.basename(video)}")
                    
                    # Add some entropy from this video to the pool immediately
                    with entropy_lock:
                        video_hash = compute_hash(video_data, "sha512")
                        entropy_pool.extend(video_hash)
                        logger.info(f"Added {len(video_hash)} bytes from {os.path.basename(video)} to pool")
                except Exception as e:
                    logger.error(f"Error processing video {os.path.basename(video)}: {str(e)}")
                    # Continue with next video instead of failing the entire process
        else:
            logger.warning("No video files available. Using system randomness only.")
            # Add more system randomness as compensation
            extra_randomness = os.urandom(1024 * 100)  # 100KB of additional randomness
            all_entropy.extend(extra_randomness)
            logger.info(f"Added {len(extra_randomness)} bytes of extra system randomness as fallback")

        # 3. Add timestamp to prevent replays
        timestamp = str(datetime.now().isoformat()).encode()
        all_entropy.extend(timestamp)

        # 4. Final hash of all entropy
        final_entropy = compute_hash(all_entropy, "sha512")
        with entropy_lock:
            entropy_pool.extend(final_entropy)

            # For larger entropy pool needs, we can generate more
            while len(entropy_pool) < ENTROPY_POOL_SIZE:
                # Generate new entropy with previous hash as seed
                hash_input = final_entropy + os.urandom(32) + str(random.random()).encode()
                final_entropy = compute_hash(hash_input, "sha512")
                entropy_pool.extend(final_entropy)

            # Update the last refresh timestamp
            last_refresh_time = time.time()
            duration = last_refresh_time - start_time
            logger.info(f"Entropy pool refreshed: {len(entropy_pool)} bytes collected in {duration:.2f} seconds")
    except Exception as e:
        logger.error(f"Error refreshing entropy pool: {str(e)}")
        # Add emergency entropy in case of error
        with entropy_lock:
            emergency_entropy = os.urandom(1024 * 10)  # 10KB emergency entropy
            entropy_pool.extend(emergency_entropy)
            last_refresh_time = time.time()
            logger.info(f"Added {len(emergency_entropy)} bytes of emergency entropy due to refresh error")

def background_entropy_refresh():
    """Background thread to refresh entropy pool."""
    global entropy_pool, last_refresh_time
    
    # Track last refresh attempt to prevent too many retries
    last_refresh_attempt = 0
    consecutive_failures = 0
    
    while True:
        try:
            # Check if we need to refresh the entropy pool
            with entropy_lock:
                current_time = time.time()
                pool_low = len(entropy_pool) < ENTROPY_POOL_SIZE // 2
                refresh_due = current_time - last_refresh_time > REFRESH_INTERVAL
                time_since_last_attempt = current_time - last_refresh_attempt
                
                # Prevent constant retries if refresh is failing
                if consecutive_failures > 3 and time_since_last_attempt < 120:
                    logger.warning(f"Skipping refresh due to {consecutive_failures} consecutive failures, next attempt in {120 - time_since_last_attempt:.0f}s")
                    time.sleep(30)
                    continue
                
                # Only trigger a refresh if one is not already in progress
                if (pool_low or refresh_due) and not refresh_in_progress.is_set():
                    logger.info(f"Background refresh triggered: pool low={pool_low}, refresh due={refresh_due}")
                    
                    # Update last attempt time
                    last_refresh_attempt = current_time
                    
                    # Set the flag to indicate a refresh is in progress
                    refresh_in_progress.set()
                    
                    # Create a cancellation event for the refresh thread
                    cancel_refresh = threading.Event()
                    
                    # Start a separate thread with timeout to prevent hanging
                    def refresh_with_cleanup():
                        try:
                            # Set a watchdog timer as a failsafe
                            watchdog_timer = threading.Timer(75, lambda: cancel_refresh.set())
                            watchdog_timer.daemon = True
                            watchdog_timer.start()
                            
                            refresh_entropy_pool()
                            
                            # Only decrement failures if successful
                            nonlocal consecutive_failures
                            consecutive_failures = max(0, consecutive_failures - 1)
                            
                            # Cancel the watchdog timer if refresh completes successfully
                            watchdog_timer.cancel()
                        except Exception as e:
                            logger.error(f"Uncaught error in refresh thread: {str(e)}")
                            consecutive_failures += 1
                            
                            # Add emergency entropy if the refresh failed
                            with entropy_lock:
                                emergency_entropy = os.urandom(1024 * 20)  # 20KB emergency entropy
                                entropy_pool.extend(emergency_entropy)
                                last_refresh_time = time.time()
                                logger.info(f"Added {len(emergency_entropy)} bytes of emergency entropy due to refresh error")
                        finally:
                            # Clear the flag when the refresh is done
                            refresh_in_progress.clear()
                            
                            # Clean up resources to help prevent leaks
                            try:
                                cv2.destroyAllWindows()
                                import gc
                                gc.collect()
                            except:
                                pass
                    
                    # Use a tighter refresh timeout (75 seconds total)
                    refresh_thread = threading.Thread(target=refresh_with_cleanup, name="EntropyRefresh")
                    refresh_thread.daemon = True
                    refresh_thread.start()
                    
                    # Set a timeout to prevent hanging indefinitely
                    refresh_thread.join(timeout=75)  # REDUCED from 90 to 75 seconds
                    
                    if refresh_thread.is_alive():
                        logger.error("Entropy refresh thread appears to be hung. Using emergency entropy.")
                        
                        # Signal the thread to cancel
                        cancel_refresh.set()
                        
                        # Add emergency entropy immediately without waiting for thread
                        emergency_entropy = os.urandom(1024 * 64)  # 64KB emergency entropy
                        with entropy_lock:
                            entropy_pool.extend(emergency_entropy)
                            last_refresh_time = time.time()
                            logger.info(f"Added {len(emergency_entropy)} bytes of emergency entropy due to timeout")
                        
                        # Increment failure counter
                        consecutive_failures += 1
                        
                        # Clear the refresh flag even if the thread is still running
                        refresh_in_progress.clear()
                        
                        # Try to forcibly clean up any hanging resources
                        try:
                            cv2.destroyAllWindows()
                            import gc
                            gc.collect()
                        except:
                            pass

            # Sleep for a while before checking again - use adaptive sleep based on pool size and failure rate
            pool_ratio = len(entropy_pool) / ENTROPY_POOL_SIZE if ENTROPY_POOL_SIZE > 0 else 0
            
            # Calculate adaptive sleep time based on pool fullness and failure history
            if consecutive_failures > 5:
                # If we've had many failures, use longer sleep to avoid thrashing
                sleep_time = min(60 * consecutive_failures, 600)  # Cap at 10 minutes
                logger.warning(f"Many consecutive failures ({consecutive_failures}), sleeping longer: {sleep_time}s")
            elif pool_ratio > 0.9:
                # If pool is very full, sleep longer (1-2 minutes)
                sleep_time = 90 
            elif pool_ratio > 0.7:
                # If pool is mostly full, sleep moderately (45s)
                sleep_time = 45
            elif pool_ratio > 0.5:
                # If pool is half full, check more frequently (30s)
                sleep_time = 30
            else:
                # If pool is low, check even more frequently (15s)
                sleep_time = 15
                
            # Log the adaptive sleep info if it's unusual
            if pool_ratio < 0.3 or consecutive_failures > 3:
                logger.info(f"Pool ratio: {pool_ratio:.2f}, failures: {consecutive_failures}, sleeping for {sleep_time}s")
                
            time.sleep(sleep_time)
            
        except Exception as e:
            logger.error(f"Error in background entropy refresh: {str(e)}")
            time.sleep(60)  # Longer sleep on error
            consecutive_failures += 1
            
            # Make sure to clear the flag if there was an error
            refresh_in_progress.clear()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})

@app.route('/api/get-seed', methods=['POST'])
@require_api_key
@rate_limit
def get_seed():
    """API endpoint that generates and returns a seed."""
    try:
        start_time = time.time()
        
        # Extract request parameters
        data = request.get_json(silent=True) or {}
        seed_size = min(int(data.get('size', 32)), 128)  # Default 32 bytes, max 128 bytes
        client_entropy = data.get('clientEntropy')
        purpose = data.get('purpose', 'general')

        # Add request context to logs
        request_id = str(uuid.uuid4())
        request_ip = request.remote_addr
        logger.info(f"Seed request {request_id} from {request_ip}: size={seed_size}, purpose={purpose}")

        # Use a faster response path for login/startup purposes to prevent app hangs
        is_critical_path = purpose in ['login', 'startup', 'initialization', 'immediate']
        
        # Check if entropy pool is being refreshed right now
        pool_is_refreshing = refresh_in_progress.is_set()
        
        # For critical path requests during refresh, respond faster with emergency entropy
        if is_critical_path and pool_is_refreshing:
            logger.info(f"Critical path request {request_id} during pool refresh - using fast path response")
            
            # Generate emergency entropy that's still cryptographically secure
            emergency_seed = os.urandom(seed_size)
            
            # If we have client entropy, mix it in
            if client_entropy:
                try:
                    client_bytes = bytes.fromhex(client_entropy)
                    mixed_seed = bytearray(seed_size)
                    for i in range(min(len(client_bytes), seed_size)):
                        mixed_seed[i] = emergency_seed[i] ^ client_bytes[i % len(client_bytes)]
                    emergency_seed = bytes(mixed_seed)
                except Exception as e:
                    logger.error(f"Error mixing client entropy: {str(e)}")
                    # Continue with just the emergency entropy
            
            # Hash the result for good measure
            final_seed = compute_hash(emergency_seed, "sha256")[:seed_size]
            
            # Return a special response indicating this was emergency entropy
            response = {
                "seed": final_seed.hex(),
                "timestamp": datetime.now().isoformat(),
                "signature": hashlib.sha256(final_seed).hexdigest(),
                "requestId": request_id,
                "prefetchDuringRefresh": True
            }
            
            elapsed = time.time() - start_time
            logger.info(f"Fast path seed request {request_id} fulfilled in {elapsed:.3f}s")
            return jsonify(response)

        # Standard path - generate the seed from the entropy pool
        seed = generate_entropy_seed(seed_size, client_entropy)

        # Return the seed with a signature for verification
        api_key = request.headers.get('X-API-Key', '')
        signature_base = seed
        if api_key in API_KEYS.values():
            signature_base = seed + api_key

        signature = hashlib.sha256(signature_base.encode()).hexdigest()
        response = {
            "seed": seed,
            "timestamp": datetime.now().isoformat(),
            "signature": signature,
            "requestId": request_id
        }

        elapsed = time.time() - start_time
        logger.info(f"Seed request {request_id} fulfilled in {elapsed:.3f}s")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error generating seed: {str(e)}")

        # Return a proper fallback response that client can handle
        fallback_seed = os.urandom(seed_size).hex()
        response = {
            "seed": fallback_seed,
            "timestamp": datetime.now().isoformat(),
            "signature": "fallback",
            "requestId": str(uuid.uuid4()),
            "fallback": True,
            "error": str(e)
        }
        return jsonify(response)

@app.route('/api/entropy-stats', methods=['GET'])
@require_api_key
def entropy_stats():
    """Returns statistics about the entropy pool (for monitoring)."""
    with entropy_lock:
        pool_size = len(entropy_pool)
        last_refresh = datetime.fromtimestamp(last_refresh_time).isoformat() if last_refresh_time > 0 else None

    stats = {
        "poolSize": pool_size,
        "poolCapacity": ENTROPY_POOL_SIZE,
        "poolUtilization": pool_size / ENTROPY_POOL_SIZE if ENTROPY_POOL_SIZE > 0 else 0,
        "lastRefresh": last_refresh,
        "videoSources": [os.path.basename(v) for v in VIDEO_FILES if os.path.exists(v)],
        "timestamp": datetime.now().isoformat()
    }

    return jsonify(stats)

if __name__ == "__main__":
    # Ensure the video directory exists
    os.makedirs(VIDEO_DIR, exist_ok=True)
    
    # Print the available video files
    available_videos = [v for v in VIDEO_FILES if os.path.exists(v)]
    logger.info(f"Available videos: {[os.path.basename(v) for v in available_videos]}")

    # Initialize entropy pool with safe defaults before starting
    logger.info("Initializing entropy pool with safe defaults...")
    with entropy_lock:
        # Add initial entropy directly to avoid any hanging issues
        initial_entropy = os.urandom(1024 * 100)  # 100KB initial entropy
        entropy_pool.extend(initial_entropy)
        last_refresh_time = time.time()
        logger.info(f"Added {len(initial_entropy)} bytes of initial entropy to bootstrap the system")
    
    # Start the initial refresh in a separate thread
    refresh_in_progress.set()  # Set the flag to indicate a refresh is in progress
    
    def initial_refresh():
        try:
            logger.info("Starting initial entropy pool refresh...")
            refresh_entropy_pool()
            logger.info("Initial entropy pool refresh completed.")
        except Exception as e:
            logger.error(f"Error in initial refresh: {str(e)}")
        finally:
            # Always clear the flag when done
            refresh_in_progress.clear()
    
    init_thread = threading.Thread(target=initial_refresh, name="InitialRefresh")
    init_thread.daemon = True
    init_thread.start()
    
    # Start background thread for ongoing entropy collection
    bg_thread = threading.Thread(target=background_entropy_refresh, name="BackgroundRefresh", daemon=True)
    bg_thread.start()

    # Always run in HTTP mode
    logger.info("Starting entropy server on port 5000 with HTTP")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)