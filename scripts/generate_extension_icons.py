#!/usr/bin/env python3
import os
from PIL import Image, ImageDraw

def bezier_point(p0, p1, p2, p3, t):
    x = (1-t)**3 * p0[0] + 3*(1-t)**2 * t * p1[0] + 3*(1-t) * t**2 * p2[0] + t**3 * p3[0]
    y = (1-t)**3 * p0[1] + 3*(1-t)**2 * t * p1[1] + 3*(1-t) * t**2 * p2[1] + t**3 * p3[1]
    return (x, y)

def generate_curve(p0, p1, p2, p3, steps=30):
    return [bezier_point(p0, p1, p2, p3, i / steps) for i in range(steps + 1)]

def main():
    print("Generating AMPass icons using Pillow...")
    
    # 1. Create a high-res canvas (512x512) for supersampling
    canvas_size = 512
    
    # Linear gradient: #4f46e5 to #7c3aed
    gradient = Image.new("RGBA", (canvas_size, canvas_size))
    pixels = gradient.load()
    for y in range(canvas_size):
        for x in range(canvas_size):
            t = (x + y) / (canvas_size * 2.0)
            r = int(79 * (1 - t) + 124 * t)
            g = int(70 * (1 - t) + 58 * t)
            b = int(229 * (1 - t) + 237 * t)
            pixels[x, y] = (r, g, b, 255)
            
    # Rounded rectangle mask (radius = 128 for 512x512, matching rx=8 in 32x32 SVG)
    mask = Image.new("L", (canvas_size, canvas_size), 0)
    mask_draw = ImageDraw.Draw(mask)
    mask_draw.rounded_rectangle([0, 0, canvas_size, canvas_size], radius=128, fill=255)
    
    # Apply mask to gradient
    background = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    background = Image.composite(gradient, background, mask)
    
    # White shield layer
    shield_layer = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    shield_draw = ImageDraw.Draw(shield_layer)
    
    # Shield points scaled from 32x32 coordinates (x16)
    # M16 8L10 12v4c0 4.4 2.6 8.5 6 10 3.4-1.5 6-5.6 6-10v-4l-6-4z
    points = [(256, 128), (160, 192), (160, 256)]
    # Curve 1
    points.extend(generate_curve((160, 256), (160, 326.4), (201.6, 392), (256, 416)))
    # Curve 2
    points.extend(generate_curve((256, 416), (310.4, 392), (352, 326.4), (352, 256)))
    points.extend([(352, 256), (352, 192), (256, 128)])
    
    # Draw shield with 0.9 opacity (230 out of 255)
    shield_draw.polygon(points, fill=(255, 255, 255, 230))
    
    # Combine layers
    icon_highres = Image.alpha_composite(background, shield_layer)
    
    # Define target directories
    ext_icon_dir = os.path.realpath(os.path.join(os.path.dirname(__file__), "../clients/browser-extension/assets/icons"))
    os.makedirs(ext_icon_dir, exist_ok=True)
    
    # Generate requested sizes
    sizes = {
        16: "icon-16.png",
        32: "icon-32.png",
        48: "icon-48.png",
        128: "icon-128.png"
    }
    
    for size, filename in sizes.items():
        # Resize using Lanczos (high-quality downscaling)
        resized = icon_highres.resize((size, size), Image.Resampling.LANCZOS)
        out_path = os.path.join(ext_icon_dir, filename)
        resized.save(out_path, "PNG")
        print(f"  Generated {filename} ({size}x{size}) -> {out_path}")
        
    print("All icons successfully generated!")

if __name__ == "__main__":
    main()
