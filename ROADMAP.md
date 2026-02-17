# WPAxFuzz UI Modernization Roadmap

## Overview
Incremental UI improvements using Rich library and Python logging, preserving all existing functionality and ASCII art.

## Current State (Last Updated: Feb 17, 2026)

**Progress**: 5/11 steps complete (45%)
**Last Action**: Step 5 - Frame Type Menu  
**Next Action**: Step 6 - Logging Configuration

## Files Modified So Far
1. `requirements.txt` - Added `rich>=13.0.0` dependency
2. `ui_utils.py` - Created new UI utilities module
3. `fuzz.py` - Updated main menu to use Rich panel (lines 30-36)
4. `fuzz.py` - Updated mode selection menu (lines 45-52)
5. `fuzz.py` - Updated frame type menu (lines 66-74)

## Guiding Principles
1. **ASCII art is sacred** - No modifications to ascii_art.py or its usage
2. **One commit per step** - Test and commit before proceeding
3. **Backward compatible** - Tool continues to work exactly as before
4. **Incremental value** - Each step provides immediate visual improvement

---

## Phase 1: Foundation

### Step 1: Add Rich Dependency ✅
**File**: `requirements.txt`  
**Change**: Add `rich>=13.0.0`  
**Test**: `pip install -r requirements.txt` completes without errors  
**Commit**: "Add Rich library dependency"  
**Status**: Completed

### Step 2: Create UI Utilities Module ✅
**File**: `ui_utils.py` (new)  
**Contents**:
- `print_menu(title, options)` - Display numbered options in a panel
- `get_input(prompt)` - Styled input prompt  
- `print_success/error/warning()` - Styled status messages  
**Test**: Import works, functions display correctly  
**Commit**: "Add basic UI utility functions"  
**Status**: Completed

---

## Phase 2: Menu Enhancements (No Logic Changes)

### Step 3: Main Menu Panel ✅
**File**: `fuzz.py`  
**Lines**: 30-36  
**Change**: Wrap menu options in Rich Panel, keep ASCII logo print unchanged  
**Implementation**:
```python
from ui_utils import print_menu

# ... ASCII art prints remain unchanged ...

print_menu("Select Operation", [
    "Fuzz Management Frames",
    "Fuzz SAE exchange",
    "Fuzz Control Frames",
    "Fuzz Data Frames (BETA)",
    "DoS attack module"
])
```
**Test**: Menu displays in box, input works  
**Commit**: "Add Rich panel to main menu"  
**Status**: Completed

### Step 4: Mode Selection Menu ✅
**File**: `fuzz.py`  
**Lines**: 45-52  
**Context**: This menu appears after selecting "Fuzz Management Frames"  
**Previous Code**:
```python
print('Type "standard" for the standard mode')
print('Type "random" for the random mode\n\n')
mode = input('Enter a choice: ').lower()
```
**Implementation**:
```python
from ui_utils import print_menu, get_input

print_menu("Select Mode", ["Standard mode (valid frame sizes)", "Random mode (random sizes)"])
mode_choice = get_input("Enter a choice (1 or 2): ")
if mode_choice == "1":
    mode = "standard"
elif mode_choice == "2":
    mode = "random"
else:
    mode = mode_choice.lower()  # Backward compatibility
```
**Test**: Mode selection works with numbers (1/2) or text ("standard"/"random")  
**Commit**: "Enhance mode selection menu with Rich panel"  
**Status**: Completed

### Step 5: Frame Type Menu ✅
**File**: `fuzz.py`  
**Lines**: 66-74  
**Context**: This menu appears after mode selection, shows 8 frame options  
**Previous Code**:
```python
print('Which frames would you like to fuzz?')
print('1) Beacon frames')
print('2) Probe request frames')
print('3) Probe response frames')
print('4) Association request frames')
print('5) Association response frames')
print('6) Reassociation request frames')
print('7) Reassociation response frames')
print('8) Authentication frames\n\n')
```
**Implementation**:
```python
print_menu("Select Frame Type to Fuzz", [
    "Beacon frames",
    "Probe request frames",
    "Probe response frames",
    "Association request frames",
    "Association response frames",
    "Reassociation request frames",
    "Reassociation response frames",
    "Authentication frames"
])
```
**Test**: All 8 options selectable  
**Commit**: "Improve frame type selection menu with Rich panel"  
**Status**: Completed

---

## Phase 3: Logging Infrastructure (CURRENT)

### Step 6: Logging Configuration (CURRENT - Do This Next)
**File**: `logging_config.py` (new)  
**Context**: Phase 2 (Menu Enhancements) is complete. Moving to Phase 3 (Logging Infrastructure).  
**Notes for Next Developer**:
- Must use `import logging.config` to use `dictConfig()`
- Test by importing and running setup_logging() in Python REPL
- Log file should be created in project root directory
- RichHandler provides colorful console output with tracebacks
  
**Contents**:
```python
import logging
import logging.config
from rich.logging import RichHandler

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(message)s"
        }
    },
    "handlers": {
        "rich": {
            "class": "rich.logging.RichHandler",
            "formatter": "default",
            "rich_tracebacks": True
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": "wpa_fuzzer.log",
            "formatter": "default"
        }
    },
    "root": {
        "handlers": ["rich", "file"],
        "level": "INFO"
    }
}

def setup_logging():
    """Configure logging with Rich console output and file output."""
    logging.config.dictConfig(LOGGING_CONFIG)
```
**Testing Commands**:
```bash
python3 -c "from logging_config import setup_logging; setup_logging(); import logging; logging.info('Test')"
ls wpa_fuzzer.log  # Verify log file was created
```
**Change**: Create new file with logging configuration using RichHandler  
**Test**: Can import and call setup_logging(), see Rich output + file output  
**Commit**: "Add logging configuration with Rich handler"

### Step 7: Logger Setup
**File**: `fuzz.py`  
**Change**: Add at top:
```python
import logging
from logging_config import setup_logging

logger = logging.getLogger(__name__)
setup_logging()
```
**Test**: No visible change yet  
**Commit**: "Initialize logging in main module"

---

## Phase 4: Print Migration

### Step 8: Migrate Informational Messages
**File**: `fuzz.py`  
**Lines**: Status messages, not user prompts  
**Change**:
- `print("Fasten your seatbelts...")` → `logger.info("...")`
- Keep all `input()` prompts as print statements
**Test**: Messages appear in console AND written to log file  
**Commit**: "Convert status messages to logging"

### Step 9: Migrate Error Messages
**File**: `fuzz.py`  
**Lines**: Error handling (lines 37, 54, 70, etc.)  
**Change**: `print(bcolors.FAIL + ...)` → `logger.error(...)`  
**Test**: Errors logged, Rich formatting applied  
**Commit**: "Convert error messages to logging"

---

## Phase 5: Fuzzing Interface (Optional)

### Step 10: Progress Indicators
**File**: `Mngmt_frames/Beacon.py` (pilot)  
**Change**: Add Rich progress bar or spinner during frame transmission  
**Test**: Visual feedback during active fuzzing  
**Commit**: "Add progress indicator to Beacon fuzzing"

### Step 11: Live Status Display
**File**: New `dashboard.py`  
**Contents**: Optional htop-style live display of:
- Connection status
- Frames sent counter
- Current test name
- Error count
**Test**: Can toggle with flag, doesn't break normal mode  
**Commit**: "Add optional live dashboard display"

---

## Quick Reference for Next Session

### Phase 2: Complete ✅
All menu enhancements in Phase 2 are now complete. Moving to Phase 3 (Logging Infrastructure).

### Current Line Numbers in fuzz.py (post-Step 5):
- Line 22: Import `from ui_utils import print_menu, get_input`
- Lines 25-28: ASCII art (unchanged)
- Lines 30-36: Main menu panel
- Lines 45-52: Mode selection menu
- Lines 66-73: Frame type menu (completed)
- **New target**: Create `logging_config.py` for Step 6

### Key Functions Available in ui_utils.py:
- `print_menu(title, options)` - Shows numbered list in panel
- `get_input(prompt)` - Styled input with Rich formatting
- `print_success/error/warning/info(message)` - Status messages

### Testing Checklist Per Step

- [ ] Code runs without errors: `python3 -m py_compile fuzz.py`
- [ ] User input flows work correctly (test the menu interaction)
- [ ] ASCII art displays unchanged
- [ ] No functional regressions
- [ ] Commit message is descriptive: `git commit -m "descriptive message"`

### Workflow for Next Developer
1. **For Step 6**: Create `logging_config.py` with the configuration shown above
2. **Test it**: Run the test commands to verify logging works
3. **Commit**: `git add logging_config.py && git commit -m "Add logging configuration with Rich handler"`
4. **Update ROADMAP**: Mark Step 6 complete and Step 7 as current
5. **For Step 7**: Import and initialize logging in `fuzz.py` top section
6. **Proceed through Phase 3-4**: Follow the same pattern

---

## Rollback Plan

If any step causes issues:
```bash
git revert HEAD  # Undo last commit
# Or
git checkout backup-branch  # Switch to pre-change branch
```

---

## Success Criteria

- [ ] All menus have Rich styling
- [ ] Logging writes to both console and file
- [ ] ASCII art completely unchanged
- [ ] Tool functionality identical to before
- [ ] No breaking changes for existing users

---

## Estimated Timeline

- Phase 1: 1-2 days ✓ Complete
- Phase 2: 2-3 days ✓ Complete (3/3 steps)
- Phase 3: 1-2 days
- Phase 4: 2-3 days
- Phase 5: 3-5 days (optional)

**Total**: 1-2 weeks for full implementation, or 1 week for core improvements (Phases 1-4)
