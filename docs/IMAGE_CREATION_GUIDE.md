# HP BIOS Toast Notification - Image Creation Guide

## Required Images

The BIOS update toast notification system requires two custom images:

### 1. HeroImage_BIOS.jpg (Banner Image)

**Technical Requirements:**
- **Dimensions:** 364 x 180 pixels (2:1 aspect ratio)
- **Format:** JPG
- **File Size:** < 1MB (recommended < 200KB for optimal performance)
- **File Name:** `HeroImage_BIOS.jpg`

**Design Specifications:**
- **Color Scheme:** HP corporate blue (#0096D6) with white/silver accents
- **Content Elements:**
  - HP logo (left or center alignment)
  - Text: "BIOS Update" or "Firmware Security Update"
  - Optional: Abstract circuit board, chip, or technology imagery
  - Professional, enterprise-appropriate design

**Creation Options:**

#### Option A: Using Canva (Recommended for Non-Designers)
1. Go to canva.com and create free account
2. Click "Custom dimensions" → Enter 364 x 180 pixels
3. Choose HP blue background (#0096D6)
4. Search for "HP logo PNG transparent" and add to canvas
5. Add text "BIOS Security Update" in bold sans-serif font (white color)
6. Optional: Add subtle gradient or tech pattern from Canva templates
7. Download as JPG → Save as `HeroImage_BIOS.jpg`

#### Option B: Using PowerPoint
1. Create new slide → Slide Size → Custom (364 x 180 pixels or 10.11" x 5" at 36 PPI)
2. Format background with HP blue (#0096D6)
3. Insert HP logo from web search (Insert → Pictures → Online Pictures)
4. Add text box with "BIOS Security Update"
5. File → Export → Save as JPG → Save as `HeroImage_BIOS.jpg`

#### Option C: Using HP Official Assets
1. Contact HP Partner Portal or Marketing department
2. Request BIOS update splash screen assets
3. Resize to 364 x 180 pixels using image editor (Paint, Photoshop, GIMP)
4. Save as `HeroImage_BIOS.jpg`

#### Option D: Screenshot HP BIOS Screen
1. Restart computer and enter BIOS (press F10 during boot on HP devices)
2. Take photo/screenshot of BIOS splash screen or main menu
3. Crop and resize to 364 x 180 pixels
4. Save as `HeroImage_BIOS.jpg`

---

### 2. BadgeImage_HP.jpg (Circular Logo)

**Technical Requirements:**
- **Dimensions:** 256 x 256 pixels (1:1 square aspect ratio)
- **Format:** JPG
- **File Size:** < 100KB
- **File Name:** `BadgeImage_HP.jpg`

**Design Specifications:**
- **Content:** HP logo centered on blue or white background
- **Important:** Image will be automatically cropped to circle by Windows
- **Design Consideration:** Keep logo centered and ensure it looks good when circular

**Creation Options:**

#### Option A: Using Canva
1. Go to canva.com
2. Create custom 256 x 256 pixel canvas
3. Choose solid blue (#0096D6) or white background
4. Search for "HP logo" and center on canvas
5. Ensure logo fits within circular area (leave margins on edges)
6. Download as JPG → Save as `BadgeImage_HP.jpg`

#### Option B: Using PowerPoint
1. Create new slide → Slide Size → Custom (256 x 256 pixels or 7.11" x 7.11" at 36 PPI)
2. Format background (blue or white)
3. Insert HP logo (Insert → Pictures → Online Pictures)
4. Center logo, keep within circular bounds
5. File → Export → Save as JPG → Save as `BadgeImage_HP.jpg`

#### Option C: Reuse Existing Badge
If the existing `badgeimage.jpg` is suitable (neutral/professional logo):
1. Copy `badgeimage.jpg` to `BadgeImage_HP.jpg`
2. Optionally edit to add HP branding

---

## Quick Start: Placeholder Images

If you need to test the toast system immediately without custom images:

### Temporary Placeholder - HeroImage_BIOS.jpg
1. Open Paint (or any image editor)
2. Create new image: 364 x 180 pixels
3. Fill with solid HP blue color (RGB: 0, 150, 214)
4. Add text "BIOS UPDATE REQUIRED" in white Arial Bold 24pt
5. Save as JPG → `HeroImage_BIOS.jpg`

### Temporary Placeholder - BadgeImage_HP.jpg
1. Open Paint
2. Create new image: 256 x 256 pixels
3. Fill with solid blue color
4. Add text "HP" in white Arial Bold 72pt (centered)
5. Save as JPG → `BadgeImage_HP.jpg`

---

## Image Verification

After creating your images, verify they meet requirements:

```powershell
# Check image dimensions and file size
Get-ChildItem "HeroImage_BIOS.jpg" | ForEach-Object {
    $img = New-Object System.Drawing.Bitmap $_.FullName
    Write-Output "HeroImage_BIOS.jpg - Width: $($img.Width)px, Height: $($img.Height)px, Size: $([math]::Round($_.Length/1KB, 2))KB"
    $img.Dispose()
}

Get-ChildItem "BadgeImage_HP.jpg" | ForEach-Object {
    $img = New-Object System.Drawing.Bitmap $_.FullName
    Write-Output "BadgeImage_HP.jpg - Width: $($img.Width)px, Height: $($img.Height)px, Size: $([math]::Round($_.Length/1KB, 2))KB"
    $img.Dispose()
}
```

**Expected Output:**
- HeroImage_BIOS.jpg - Width: 364px, Height: 180px, Size: < 1000KB
- BadgeImage_HP.jpg - Width: 256px, Height: 256px, Size: < 100KB

---

## File Placement

Place both image files in the same directory as the toast scripts:

```
<project-root>\
├── Toast_Notify_BIOS.ps1
├── Toast_Snooze_Handler.ps1
├── Toast_Reboot_Scheduler.ps1
├── BIOS_Update.xml
├── HeroImage_BIOS.jpg     ← Place here
├── BadgeImage_HP.jpg       ← Place here
└── (other files...)
```

For MEMCM deployment, include both images in the package source folder.

---

## Resources

- **HP Brand Guidelines:** https://www.hp.com/us-en/hp-information/brand.html
- **HP Logo Downloads:** Search "HP logo PNG transparent" on Google Images
- **Toast Image Guidelines:** https://docs.microsoft.com/en-us/windows/uwp/design/shell/tiles-and-notifications/toast-ux-guidance
- **Free Image Editors:**
  - Canva: https://www.canva.com
  - GIMP (free Photoshop alternative): https://www.gimp.org
  - Paint.NET: https://www.getpaint.net

---

## Troubleshooting

**Images Not Displaying in Toast:**
1. Verify file names match exactly: `HeroImage_BIOS.jpg` and `BadgeImage_HP.jpg`
2. Check files are in correct directory
3. Verify file format is JPG (not PNG or other)
4. Check Toast_Notify_BIOS.ps1 lines 343-344 reference correct paths
5. Review log file: `C:\Windows\Temp\{GUID}.log` for image loading errors

**Images Look Distorted:**
- HeroImage: Must be exactly 364 x 180 pixels (2:1 ratio)
- BadgeImage: Must be 256 x 256 pixels (1:1 ratio) or image will stretch

**Badge Image Not Circular:**
- This is normal - Windows automatically crops square image to circle
- Ensure logo is centered in the square canvas
