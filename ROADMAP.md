# WPAxFuzz UI Modernization Roadmap

## Overview
Incremental UI improvements using Rich library and Python logging, preserving all existing functionality and ASCII art.

## Current State (Last Updated: Feb 17, 2026)

**Progress**: 6/11 steps complete (55%)
**Status**: Ready for handoff - Step 7 is next
**Last Action**: Step 6 - Created logging_config.py with RichHandler
**Next Action**: Step 7 - Initialize logger in fuzz.py (see detailed instructions below)
**Assigned To**: Next available developer

## Files Modified So Far
1. `requirements.txt` - Added `rich>=13.0.0` and `pygments>=2.0.0` dependencies
2. `ui_utils.py` - Created new UI utilities module
3. `fuzz.py` - Updated main menu to use Rich panel (lines 30-36)
4. `fuzz.py` - Updated mode selection menu (lines 45-52)
5. `fuzz.py` - Updated frame type menu (lines 66-74)
6. `logging_config.py` - Created logging configuration with RichHandler
7. `requirements.txt` - Added `pygments>=2.0.0` for Rich tracebacks

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

### Step 6: Logging Configuration ✅
**File**: `logging_config.py` (new)  
**Context**: Phase 2 (Menu Enhancements) is complete. Moving to Phase 3 (Logging Infrastructure).  
**Notes**:
- Must use `import logging.config` to use `dictConfig()`
- Added `pygments>=2.0.0` to requirements.txt (required by RichHandler for tracebacks)
- Log file created in project root directory
- RichHandler provides colorful console output with tracebacks
  
**Implementation**:
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
**Test**: Logging outputs to both console (Rich formatted) and file  
**Commit**: "Add logging configuration with Rich handler"  
**Status**: Completed

### Step 7: Logger Setup (CURRENT - Do This Next)
**File**: `fuzz.py`  
**Context**: Now that logging_config.py exists, initialize logging in the main module. This enables the logger to be used in Steps 8-9 for print migration.  
**Location**: Add near the top of fuzz.py, after imports but before any code runs  
**Current Code at Lines 21-22**:
```python
import ascii_art
from ui_utils import print_menu, get_input
```
**Exact Change Required**: Insert after line 22 (after the ui_utils import):
```python
import logging
from logging_config import setup_logging

logger = logging.getLogger(__name__)
setup_logging()
```
**Resulting code structure (lines 21-28)**:
```python
import ascii_art
from ui_utils import print_menu, get_input
import logging
from logging_config import setup_logging

logger = logging.getLogger(__name__)
setup_logging()
```
**Important Notes**:
- Place these imports AFTER `from ui_utils import print_menu, get_input` (line 22)
- This ensures ui_utils is imported before logging setup
- The logger variable will be used in Steps 8-9 to replace print statements
- No functional changes yet - just initialization
  
**Test**: 
1. `python3 -m py_compile fuzz.py` - should have no errors
2. Verify imports work: `python3 -c "import fuzz"` (may show ASCII art, that's OK)
  
**Verification** (optional but recommended):
Temporarily add after `setup_logging()`: `logger.info("WPAxFuzz starting...")`
Then run: `python3 fuzz.py` (will need to Ctrl+C after menus), check that:
- Console shows: `[TIME] INFO     WPAxFuzz starting...`
- File wpa_fuzzer.log contains the message
Remove the test line before committing.
  
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

### Current State (post-Step 6):
**Phase 3 (Logging Infrastructure): In Progress - 1/2 steps complete**

**New Files Created**:
- `logging_config.py` - Logging configuration with RichHandler
- `wpa_fuzzer.log` - Log file (created at runtime)

**Current Line Numbers in fuzz.py**:
- Line 22: Import `from ui_utils import print_menu, get_input`
- Lines 25-28: ASCII art (unchanged)
- Lines 30-36: Main menu panel
- Lines 45-52: Mode selection menu
- Lines 66-73: Frame type menu
- **Next target**: Initialize logging in fuzz.py (Step 7)

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

**Current Status: Ready to Start Step 7**

The codebase is in a stable state with:
- ✅ Phase 1 (Foundation): Complete
- ✅ Phase 2 (Menu Enhancements): Complete - all menus use Rich panels
- 🎯 Phase 3 (Logging Infrastructure): 50% complete - configuration done, initialization pending
- ⏳ Phase 4 (Print Migration): Not started - waiting for Step 7

**Step-by-Step Instructions**:

**Step 7 (Current - Logging Initialization)**:
1. Read fuzz.py lines 1-25 to understand current import structure
2. Add after line 22 (after `from ui_utils import print_menu, get_input`):
   ```python
   import logging
   from logging_config import setup_logging
   
   logger = logging.getLogger(__name__)
   setup_logging()
   ```
3. Test: `python3 -m py_compile fuzz.py` (must pass)
4. Optional verification: Add temporary `logger.info("Test")` line, run `python3 fuzz.py`, check output, remove test line
5. Update ROADMAP: Mark Step 7 complete, Step 8 as current
6. Commit: `git add fuzz.py ROADMAP.md && git commit -m "Initialize logging in main module"`

**Step 8 (Next - Info Messages)**:
- Find all `print("Fasten your seatbelts...")` style messages in fuzz.py
- Convert to `logger.info("...")`
- Keep all `input()` prompts as-is (don't convert to logging)
- Test and commit

**Step 9 (Next - Error Messages)**:
- Find all `print(bcolors.FAIL + ...)` error messages
- Convert to `logger.error("...")`
- RichHandler will automatically format errors in red
- Test and commit

**Post-Phase 3**:
- All menus will have Rich styling (Phase 2) ✓
- All status messages will go to both console AND log file (Phase 3)
- Tool will have complete logging infrastructure
- Ready for optional Phase 5 enhancements (progress bars, dashboard)

---

## Handoff Notes for Next Developer

### What You Should Know Before Starting Step 7

**State of the Codebase**:
- All menu enhancements (Phase 2) are complete and working
- `logging_config.py` exists and is functional - DON'T modify it
- `ui_utils.py` has all helper functions available
- `fuzz.py` has Rich-styled menus at lines 30-36, 45-52, and 66-73

**Critical Context**:
1. **Line 25 in fuzz.py** has `print(ascii_art.logo)` - this MUST remain unchanged
2. **The logger instance** you'll create in Step 7 will be used in Steps 8-9
3. **Import order matters**: Import logging_config AFTER ui_utils to avoid circular imports
4. **Testing**: Always run `python3 -m py_compile fuzz.py` before committing
5. **No functional changes** in Step 7 - it's just setup for Steps 8-9

**Files You Will Modify**:
- Step 7: `fuzz.py` only (add logging initialization)
- Step 8: `fuzz.py` (convert info prints to logger.info())
- Step 9: `fuzz.py` (convert error prints to logger.error())

**Files You Should NOT Modify**:
- `logging_config.py` (already complete)
- `ui_utils.py` (already complete)
- `ascii_art.py` (sacred - never modify)

**Common Pitfalls**:
- Don't put logging imports at the very top - put them after ui_utils import
- Don't forget to remove any test logger.info() calls before committing
- Don't modify any existing functionality - only convert print to logger

**Quick Verification After Step 7**:
```bash
python3 -c "import fuzz" 2>&1 | head -5  # Should show ASCII art without errors
git diff fuzz.py  # Should show only the 4 new lines (imports + setup)
```

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
