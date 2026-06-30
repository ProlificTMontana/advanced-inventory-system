# AIMS Barcode Scanner Testing Guide

## Prerequisites

1. **Database Migration Applied**: Ensure `supabase-scanner-migration.sql` has been run in Supabase SQL Editor
2. **Build Successful**: Run `npm run build` to verify no TypeScript errors
3. **PWA Installed**: Install the AIMS PWA on your mobile device for testing camera permissions
4. **Test Data**: Have at least one item with a barcode assigned in the database

## Testing Scenarios

### 1. Rapid Successive Scans (Batch Mode)

**Objective**: Test continuous scanning without manual intervention

**Steps**:
1. Navigate to `/scan` route
2. Enable "Batch Mode" toggle
3. Enable "Hands-Free Mode" toggle
4. Scan multiple items in quick succession
5. Verify each scan triggers the result card
6. Verify haptic feedback (vibration) on each scan
7. Verify sound feedback (beep) on each scan
8. Verify scan history updates in real-time

**Expected Results**:
- Each scan processes independently
- No cooldown between scans in hands-free mode
- Haptic and sound feedback on each successful scan
- Scan history shows all scanned barcodes

**Failure Indicators**:
- Scans are ignored/dropped
- No haptic or sound feedback
- Scan history is incomplete

---

### 2. Scanning Unknown Barcode

**Objective**: Test handling of barcodes not in database

**Steps**:
1. Ensure "Single Mode" is active
2. Scan a barcode that doesn't exist in the database
3. Verify "Unknown Barcode" dialog appears
4. Test "Create New Item" button
5. Test "Link to Existing Item" button
6. Test "Dismiss" button

**Expected Results**:
- Unknown barcode dialog shows the scanned barcode
- All three options are functional
- Dialog closes appropriately after each action

**Failure Indicators**:
- Dialog doesn't appear
- Barcode value is incorrect
- Buttons don't respond

---

### 3. Going Offline Mid-Scan

**Objective**: Test offline queue survival and sync on reconnect

**Steps**:
1. Navigate to `/scan` route
2. Scan an item and note the quantity
3. Disconnect device from network (airplane mode or disable WiFi)
4. Verify "Working Offline" banner appears
5. Scan another item and perform stock adjustment
6. Reconnect to network
7. Verify offline sync processes automatically
8. Check database to confirm quantity was updated

**Expected Results**:
- Offline banner appears when disconnected
- Scans are queued in IndexedDB
- Pending count shows in sync status
- Sync processes automatically on reconnect
- Database reflects all offline changes

**Failure Indicators**:
- Scans fail when offline
- Data is lost during offline period
- Sync doesn't trigger on reconnect
- Database has incorrect quantities

---

### 4. Real-Time Sync Verification

**Objective**: Test Supabase Realtime updates across multiple clients

**Steps**:
1. Open AIMS PWA in two separate browser tabs (or devices)
2. Navigate to `/scan` in both tabs
3. In Tab 1, scan an item and perform stock adjustment
4. In Tab 2, navigate to `/items` or `/dashboard`
5. Verify the quantity updates within 2 seconds
6. Repeat with different items

**Expected Results**:
- Changes appear in Tab 2 within 2 seconds
- No manual refresh required
- Both tabs show consistent data

**Failure Indicators**:
- Changes don't appear in Tab 2
- Manual refresh required
- Data inconsistency between tabs

---

### 5. Camera Permission Handling

**Objective**: Test graceful handling of camera permission states

**Steps**:
1. Navigate to `/scan` route
2. Grant camera permission when prompted
3. Verify scanner initializes successfully
4. Close scanner and revoke camera permission in browser settings
5. Navigate to `/scan` again
6. Verify appropriate error message displays
7. Test on iOS Safari PWA (if available)
8. Test on Android Chrome PWA (if available)

**Expected Results**:
- Permission prompt appears on first access
- Scanner initializes after granting permission
- Clear error message when permission denied
- Error message is actionable

**Failure Indicators**:
- No permission prompt
- App crashes on permission denial
- Unclear error message
- Platform-specific issues

---

### 6. Torch Toggle Functionality

**Objective**: Test flashlight toggle on supported devices

**Steps**:
1. Navigate to `/scan` route
2. Test in a dark environment
3. Click the torch/flashlight button
4. Verify flashlight turns on
5. Click again to turn off
6. Test on device without torch support
7. Verify graceful degradation

**Expected Results**:
- Torch toggles on/off on supported devices
- Button icon changes state
- No errors on unsupported devices
- Console warning for unsupported devices

**Failure Indicators**:
- Torch doesn't toggle
- Button doesn't update
- App crashes on unsupported devices

---

### 7. Mode Persistence

**Objective**: Test that scan mode preferences persist across sessions

**Steps**:
1. Navigate to `/scan` route
2. Enable "Batch Mode"
3. Enable "Hands-Free Mode"
4. Close the app/browser
5. Reopen and navigate to `/scan`
6. Verify both modes are still enabled
7. Disable modes and refresh
8. Verify modes remain disabled

**Expected Results**:
- Mode preferences persist in localStorage
- Settings load correctly on app restart
- Toggles reflect saved state

**Failure Indicators**:
- Modes reset to default on refresh
- localStorage not being used
- Inconsistent state

---

### 8. IndexedDB Queue Survival

**Objective**: Test that offline queue survives browser close

**Steps**:
1. Disconnect device from network
2. Scan multiple items and perform adjustments
3. Close the browser/app completely
4. Reopen the browser/app
5. Reconnect to network
6. Verify sync processes queued scans
7. Check database for correct quantities

**Expected Results**:
- Queue survives browser close
- All queued scans sync on reconnect
- No data loss
- IndexedDB persists correctly

**Failure Indicators**:
- Queue is cleared on browser close
- Scans are lost
- Incomplete sync

---

### 9. Stock Adjustment Validation

**Objective**: Test that stock adjustments respect inventory constraints

**Steps**:
1. Navigate to `/scan` route
2. Scan an item with low quantity
3. Attempt to remove more than available
4. Verify error message appears
5. Verify quantity doesn't go negative
6. Add stock and verify transaction is created
7. Check transaction log in database

**Expected Results**:
- Cannot remove more than available
- Appropriate error message
- Transaction log records all changes
- Quantity updates correctly

**Failure Indicators**:
- Negative quantities allowed
- No error on invalid removal
- Transaction log incomplete

---

### 10. Mobile UX Testing

**Objective**: Test mobile-optimized features on actual devices

**Steps**:
1. Test on iOS Safari PWA
2. Test on Android Chrome PWA
3. Verify large tap targets work with touch
4. Verify camera view fills screen appropriately
5. Verify scan frame is visible in various lighting
6. Test in portrait and landscape orientations
7. Verify keyboard doesn't interfere with scanner

**Expected Results**:
- Touch targets are easily tappable (44px minimum)
- Camera view is responsive
- Scan frame is visible in all lighting
- Orientation changes handled gracefully
- No keyboard interference

**Failure Indicators**:
- Touch targets too small
- Camera view distorted
- Scan frame invisible in bright light
- Orientation breaks layout
- Keyboard covers scanner

---

## Performance Testing

### Bundle Size Verification

Run `npm run build` and check the output:

```bash
npm run build
```

Expected bundle size increase: < 300KB (including @zxing/library)

### Scan Performance

1. Test scan speed with various barcode types:
   - EAN-13
   - UPC
   - Code 128
   - QR codes

2. Measure time from scan to result card appearance
3. Expected: < 500ms for most barcodes

---

## Accessibility Testing

1. **Screen Reader**: Test with VoiceOver (iOS) or TalkBack (Android)
2. **Keyboard Navigation**: Test scanner can be closed with Escape key
3. **Color Contrast**: Verify all text meets WCAG AA standards
4. **Focus Management**: Verify focus moves appropriately after scan

---

## Browser Compatibility

Test on the following browsers:

- **Desktop**: Chrome, Firefox, Safari, Edge
- **Mobile**: iOS Safari, Android Chrome
- **PWA**: iOS Safari (added to home screen), Android Chrome (added to home screen)

---

## Troubleshooting

### Camera Not Working

1. Check browser permissions
2. Verify HTTPS is required (camera API requires secure context)
3. Check if another app is using the camera
4. Try refreshing the page

### Scans Not Recognizing

1. Ensure barcode is well-lit
2. Hold camera at appropriate distance (6-12 inches)
3. Try different barcode formats
4. Clean camera lens

### Sync Not Working

1. Check network connection
2. Verify Supabase Realtime is enabled for the project
3. Check browser console for errors
4. Verify RLS policies allow writes

### Build Errors

1. Run `npm install` to ensure dependencies are up to date
2. Clear node_modules and reinstall: `rm -rf node_modules && npm install`
3. Check TypeScript version compatibility
4. Verify all imports are correct

---

## Success Criteria

All tests pass when:
- ✅ Database migration applied successfully
- ✅ Build completes without errors
- ✅ Camera works on both iOS and Android
- ✅ Offline queue survives browser close
- ✅ Real-time sync works within 2 seconds
- ✅ All mobile UX features functional
- ✅ Bundle size increase < 300KB
- ✅ No console errors during normal operation
