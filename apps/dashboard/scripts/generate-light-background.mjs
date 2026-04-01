#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import sharp from 'sharp';

const ROOT = path.resolve(process.cwd());
const inputPath = path.join(ROOT, 'public', 'Branding', 'background-blue.avif');
const outputPath = path.join(
  ROOT,
  'public',
  'Branding',
  'background-light.avif'
);

async function main() {
  try {
    const input = await fs.readFile(inputPath);

    // Decode to raw sRGB so we can manipulate lightness precisely.
    const base = sharp(input, {
      unlimited: true,
      sequentialRead: true,
    }).toColorspace('srgb');
    const { data, info } = await base
      .ensureAlpha()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const channels = info.channels; // expect 4 with alpha
    const width = info.width;
    const out = Buffer.allocUnsafe(data.length);

    function rgbToHsl(r, g, b) {
      r /= 255;
      g /= 255;
      b /= 255;
      const max = Math.max(r, g, b),
        min = Math.min(r, g, b);
      let h,
        s,
        l = (max + min) / 2;
      if (max === min) {
        h = 0;
        s = 0;
      } else {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
          case r:
            h = (g - b) / d + (g < b ? 6 : 0);
            break;
          case g:
            h = (b - r) / d + 2;
            break;
          default:
            h = (r - g) / d + 4;
            break;
        }
        h /= 6;
      }
      return [h, s, l];
    }

    function hue2rgb(p, q, t) {
      if (t < 0) t += 1;
      if (t > 1) t -= 1;
      if (t < 1 / 6) return p + (q - p) * 6 * t;
      if (t < 1 / 2) return q;
      if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
      return p;
    }

    function hslToRgb(h, s, l) {
      let r, g, b;
      if (s === 0) {
        r = g = b = l;
      } else {
        const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
        const p = 2 * l - q;
        r = hue2rgb(p, q, h + 1 / 3);
        g = hue2rgb(p, q, h);
        b = hue2rgb(p, q, h - 1 / 3);
      }
      return [
        Math.max(0, Math.min(255, Math.round(r * 255))),
        Math.max(0, Math.min(255, Math.round(g * 255))),
        Math.max(0, Math.min(255, Math.round(b * 255))),
      ];
    }

    // Invert only the lightness channel L' = 1 - L, correct purple/magenta drift,
    // and clamp very light highlights to a white→cyan fade
    for (let i = 0; i < data.length; i += channels) {
      const r = data[i];
      const g = data[i + 1];
      const b = data[i + 2];
      const a = data[i + 3];
      let [h, s, l] = rgbToHsl(r, g, b);
      let lInv = 1 - l;
      // Compute x position to taper saturation near the left edge
      const pixel = (i / channels) >>> 0;
      const x = pixel % width;
      const xNorm = x / width; // 0..1
      // Convert hue to degrees for readability
      let hd = h * 360;
      // Stronger correction for purple/magenta range (240°–350°) toward brand blue (~215°)
      if (s > 0.15 && hd > 240 && hd < 350) {
        const target = 215; // deep blue
        const mix = 0.35; // 35% pull toward blue
        hd = hd * (1 - mix) + target * mix;
        s = s * 0.9; // damp saturation slightly
      }
      // Gentle correction for reddish edge (350°–360° and 0°–20°) to avoid pink
      if (s > 0.15 && (hd >= 350 || hd < 20)) {
        const target = 210;
        const mix = 0.25;
        // Wrap-aware blend toward target
        const hdWrapped = hd >= 350 ? hd - 360 : hd; // map 350..360 => -10..0
        const blended = hdWrapped * (1 - mix) + (target - 360) * mix; // keep near -
        hd = blended < 0 ? blended + 360 : blended;
        s = s * 0.92;
      }
      // For very light tones after inversion, force a white→cyan fade
      // to avoid any pink/purple cast in highlights.
      if (lInv > 0.9) {
        // If hue is anywhere near red/purple (340°–360° or 0°–80° or 240°–320°), clamp strongly
        if (hd >= 340 || hd < 80 || (hd >= 240 && hd <= 320)) {
          hd = 195; // cyan
          s = Math.min(s, 0.1); // keep highlights close to white
        } else {
          // Otherwise blend toward cyan moderately
          const mix = 0.5;
          hd = hd * (1 - mix) + 195 * mix;
          s = Math.min(s, 0.15);
        }
      } else if (lInv > 0.78) {
        if (hd >= 350 || hd < 40 || (hd >= 250 && hd <= 330)) {
          const mix = 0.45;
          hd = hd * (1 - mix) + 195 * mix;
          s = Math.min(s, 0.2);
        } else {
          const mix = 0.3;
          hd = hd * (1 - mix) + 195 * mix;
          s = Math.min(s, 0.25);
        }
      }
      // Additional left-edge correction to avoid a heavy cyan band
      // Apply a 0.4-width taper from 40% to 0% (strongest at the very left)
      if (xNorm < 0.4) {
        const t = 1 - xNorm / 0.4; // 0..1 (1 at left edge)
        // Strong desaturation toward the edge (up to -60%)
        const satScale = 1 - 0.6 * t;
        s = Math.max(0, s * satScale);
        // Slight lightness lift toward white to soften the band
        lInv = Math.min(1, lInv + 0.08 * t);
        // Ease hue toward a softer cyan a little (low influence)
        const mix = 0.08 * t; // up to 8% blend toward 200°
        hd = hd * (1 - mix) + 200 * mix;
      }
      h = (hd % 360) / 360;
      const [nr, ng, nb] = hslToRgb(h, s, lInv);
      out[i] = nr;
      out[i + 1] = ng;
      out[i + 2] = nb;
      out[i + 3] = a;
    }

    // Build a left-edge white gradient overlay to further soften cyan band
    const leftOverlay = Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${info.width}" height="${info.height}" viewBox="0 0 ${info.width} ${info.height}">
        <defs>
          <linearGradient id="leftFade" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="#ffffff" stop-opacity="0.65"/>
            <stop offset="35%" stop-color="#ffffff" stop-opacity="0.28"/>
            <stop offset="45%" stop-color="#ffffff" stop-opacity="0.12"/>
            <stop offset="55%" stop-color="#ffffff" stop-opacity="0.06"/>
            <stop offset="100%" stop-color="#ffffff" stop-opacity="0"/>
          </linearGradient>
        </defs>
        <rect x="0" y="0" width="100%" height="100%" fill="url(#leftFade)"/>
      </svg>`
    );

    const transformed = await sharp(out, {
      raw: { width: info.width, height: info.height, channels },
    })
      .toColorspace('srgb')
      .composite([{ input: leftOverlay, blend: 'screen' }])
      .toFormat('avif', { quality: 65, chromaSubsampling: '4:4:4', effort: 4 })
      .toBuffer();

    await fs.writeFile(outputPath, transformed);
    console.log('Generated:', path.relative(ROOT, outputPath));
  } catch (err) {
    console.error('Failed to generate light background:', err);
    process.exitCode = 1;
  }
}

main();
