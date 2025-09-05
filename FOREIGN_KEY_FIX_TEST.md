# Foreign Key Constraint Fix Test Guide

## Problem Summary
The extension was failing to record HTTP request history with the error:
```
[!] 保存历史记录失败: [SQLITE_CONSTRAINT_FOREIGNKEY] A foreign key constraint failed (FOREIGN KEY constraint failed)
```

## Root Cause
- HTTP requests with `requestId = -1` (unsaved requests) were trying to create history records
- The history table had a foreign key constraint requiring valid `request_id` from requests table
- No request with `id = -1` exists in the requests table, causing constraint failure

## Solution Implemented

### 1. Database Schema Update
- **File**: `DatabaseManager.java:275-294`
- **Change**: Updated foreign key constraint from `ON DELETE CASCADE` to `ON DELETE SET NULL`
- **Added**: `updateHistoryTableForeignKey()` method to migrate existing databases

### 2. HistoryDAO Modifications
- **File**: `HistoryDAO.java`
- **Changes**:
  - `saveHistory(RequestResponseRecord)`: Added NULL handling for `requestId <= 0` (lines 137-143)
  - `saveHistory(int, IRequestInfo, byte[], byte[])`: Added NULL handling for `requestId <= 0` (lines 68-73)
  - `getAllHistory()`: Added NULL handling when reading `request_id` from database (lines 237-243)
  - `getHistoryById()`: Added NULL handling (lines 295-302)
  - `getHistoryByRequestId()`: Added NULL handling (lines 443-450)

### 3. HistoryRecordingService Updates
- **File**: `HistoryRecordingService.java`
- **Changes**: Enhanced logging to distinguish between saved and unsaved requests (lines 147-151, 188-192)

## Test Scenarios

### Test 1: Unsaved Request History Recording
1. **Setup**: Fresh Burp Suite session with the updated extension
2. **Action**: Create a new HTTP request but **don't save it** to the request list
3. **Send**: Send the request using the "Send" button
4. **Expected Results**:
   - ✅ Request should complete successfully
   - ✅ History record should appear in the history panel
   - ✅ Log should show: `[+] HTTP请求历史记录已保存（未保存请求），ID: X`
   - ✅ No foreign key constraint errors

### Test 2: Saved Request History Recording
1. **Setup**: Burp Suite with the updated extension
2. **Action**: Create a new HTTP request and **save it** to the request list
3. **Send**: Send the request from the saved requests list
4. **Expected Results**:
   - ✅ Request should complete successfully
   - ✅ History record should appear in the history panel
   - ✅ Log should show: `[+] HTTP请求历史记录已保存（关联请求ID: Y），ID: X`
   - ✅ No foreign key constraint errors

### Test 3: Failed Request History Recording
1. **Setup**: Burp Suite with the updated extension
2. **Action**: Send a request to an invalid/unreachable host
3. **Expected Results**:
   - ✅ Request should fail gracefully
   - ✅ History record should appear in the history panel with failure details
   - ✅ Log should show: `[+] HTTP失败请求历史记录已保存（未保存请求），ID: X`
   - ✅ No foreign key constraint errors

### Test 4: Database Schema Migration
1. **Setup**: Existing database with old schema
2. **Action**: Start the extension with existing database
3. **Expected Results**:
   - ✅ Log should show: `[*] 检测到旧的外键约束定义，正在更新...`
   - ✅ Log should show: `[+] 历史表外键约束更新完成`
   - ✅ Extension should work normally after migration

## Verification Steps

### 1. Check Database Schema
After running the extension, verify the schema:
```sql
-- Check foreign key constraint
SELECT sql FROM sqlite_master WHERE type='table' AND name='history';
-- Should show: FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE SET NULL
```

### 2. Verify History Records
Check that both saved and unsaved requests appear in history:
```sql
-- Count total history records
SELECT COUNT(*) FROM history;

-- Count records with NULL request_id (unsaved requests)
SELECT COUNT(*) FROM history WHERE request_id IS NULL;

-- Count records with valid request_id (saved requests)
SELECT COUNT(*) FROM history WHERE request_id > 0;
```

### 3. Check Request Association
Verify request ID association works correctly:
```sql
-- Check that saved requests have valid associations
SELECT h.id, h.request_id, r.id as actual_request_id 
FROM history h 
LEFT JOIN requests r ON h.request_id = r.id 
WHERE h.request_id IS NOT NULL;
```

## Expected Logging Messages

### Success Indicators:
- `[+] 数据库连接重新建立成功` - Database connection restored
- `[+] HTTP请求历史记录已保存（未保存请求），ID: X` - Unsaved request recorded
- `[+] HTTP请求历史记录已保存（关联请求ID: Y），ID: X` - Saved request recorded
- `[+] 历史表外键约束更新完成` - Schema migration completed

### Error Indicators (should be rare):
- `[!] 保存历史记录失败: 数据库连接无效` - Database connection issue
- `[!] 历史记录任务队列已满，无法添加任务` - Recording service overloaded

## Rollback Plan
If issues occur:
1. Stop Burp Suite
2. Delete the database file: `~/.burp/repeater_manager.db`
3. Restart Burp Suite (fresh database will be created)
4. Alternatively, restore from backup if available

## Performance Impact
- **Minimal**: The fix adds negligible overhead
- **Database**: NULL handling is efficient in SQLite
- **Memory**: No additional memory usage
- **CPU**: Minimal additional processing for NULL checks

## Conclusion
This fix resolves the foreign key constraint issue while maintaining:
- ✅ All HTTP requests are recorded in history
- ✅ Database integrity for saved request associations
- ✅ Backward compatibility with existing functionality
- ✅ Minimal performance impact
- ✅ Clear logging for debugging

The solution allows unsaved requests to have history records without breaking the referential integrity of saved requests.