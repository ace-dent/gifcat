# gifcat

Concatenate multiple single-frame GIFs into a single looping animation.  

🅰️😸🅱️➡️🆎

<br>

## 🚧 **Alpha / Experimental** 🚧
_This project is in an early alpha state. Use at your own risk—functionality may be incomplete, unsafe, or incorrect._

---

## 📝 Features

- Preserves raw LZW-compressed image data for pixel-perfect frames.
- Maintains transparency, disposal methods, and delay times (defaults applied if missing).
- Retains and compares global palettes; embeds local palettes on mismatch.
- Inserts a Netscape application extension to enable infinite looping if absent.
- Validates inputs: GIF signature, file size boundaries, nonzero screen dimensions,
presence of a single image descriptor, and sub-block bounds.
- Ensures subsequent frames fit within the initial screen dimensions.
- Supports inserting a 1×1 “dummy” frame referencing the first frame’s top-left color.

## 🚀 Usage

```sh
gifcat output.gif [-fallback-delay CS] frame0.gif [frame1.gif ...]
```

- `output.gif`: path for the resulting animated GIF.
- `-fallback-delay CS`: (optional) delay in centiseconds when no delay is specified in input.
- `frameX.gif`: single-frame GIFs to concatenate.
- Use literal `dummy` as a frame to append a 1×1px placeholder with default delay and disposal=1.

## 🛠️ Building

This is a standalone C program. Ensure you have a C compiler (e.g., `gcc` or `clang`) and standard libraries.To build:

```sh
gcc -std=c11 -o gifcat gifcat.c
```

or 

```sh
clang -o gifcat gifcat.c
```

## ⚠️ Disclaimer

- **Alpha / Experimental**: Behavior is not guaranteed. May crash or produce invalid GIFs.
- Not safe for untrusted input—use proper sandboxing if processing third-party files.
- No support for multi-frame input GIFs; only single-frame files are accepted.

## 📄 License

This project is licensed under the MIT License. See [LICENSE](/LICENSE) for details.