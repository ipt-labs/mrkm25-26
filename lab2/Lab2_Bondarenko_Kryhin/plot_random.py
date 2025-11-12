import os
import numpy as np
import matplotlib.pyplot as plt
from Crypto import Random

def generate_randomness_bitmap(width=512, height=512, filename):
    total_bytes = width * height
    print(f"Generating {width}x{height} bitmap ({total_bytes} bytes) from PyCryptodome CSPRNG...")

    try:
        # get random bytes
        random_data_bytes = Random.get_random_bytes(total_bytes)

        # convert bytes (0-255) into array of unsigned 8-bit integers.
        random_array = np.frombuffer(random_data_bytes, dtype=np.uint8)

        # transform array to matrix
        image_matrix = random_array.reshape((height, width))

        plt.figure(figsize=(width / 100, height / 100), dpi=100)
        
        plt.imshow(image_matrix, cmap='gray', interpolation='nearest')
        
        plt.title(f'PyCryptodome CSPRNG Randomness ({width}x{height})')
        plt.axis('off')
        
        plt.savefig(filename, bbox_inches='tight', pad_inches=0.1)

        print(f"Generated and saved visualization to {filename}")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    IMAGE_WIDTH = 512
    IMAGE_HEIGHT = 512
    OUTPUT_FILENAME = 'pycryptodome_random_image.png' 

    generate_randomness_bitmap(IMAGE_WIDTH, IMAGE_HEIGHT, OUTPUT_FILENAME)
