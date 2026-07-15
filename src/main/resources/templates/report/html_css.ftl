<#-- CSS 样式（静态，无动态数据） -->
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px; color: #333; line-height: 1.6; max-width: 1100px; margin: 0 auto;
    padding: 20px; background: #f5f5f5; }
  .header { background: #1a237e; color: white; padding: 30px; border-radius: 8px; margin-bottom: 24px; }
  .header h1 { font-size: 24px; margin-bottom: 8px; }
  .header .meta { font-size: 13px; opacity: 0.85; }
  h2 { font-size: 20px; margin: 28px 0 16px; color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 8px; }
  h3 { font-size: 16px; margin: 16px 0 10px; color: #283593; }
  h4 { font-size: 15px; margin: 14px 0 8px; }
  h5 { font-size: 13px; margin: 10px 0 6px; color: #555; font-weight: 600; }
  .summary-cards { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .card { flex: 1; min-width: 140px; background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .card .number { font-size: 32px; font-weight: 700; }
  .card .label { font-size: 13px; color: #666; margin-top: 4px; }
  .card.total { border-top: 4px solid #1a237e; }
  .card.escalated { border-top: 4px solid #d32f2f; }
  .card.escalated .number { color: #d32f2f; }
  .card.safe { border-top: 4px solid #2e7d32; }
  .card.safe .number { color: #2e7d32; }
  .card.error { border-top: 4px solid #f57c00; }
  .card.error .number { color: #f57c00; }
  table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px;
    overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 16px; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #e0e0e0; }
  th { background: #1a237e; color: white; font-weight: 600; font-size: 13px; }
  tr:hover td { background: #f5f5f5; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; color: white; }
  .badge.escalated { background: #d32f2f; }
  .badge.safe { background: #2e7d32; }
  .badge.error { background: #f57c00; }
  .badge.baseline { background: #1565C0; }
  .endpoint-section { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .endpoint-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .endpoint-header .method { font-weight: 700; color: #1a237e; }
  .baseline-title { color: #1565C0; border-bottom: 1px dashed #90CAF9; padding-bottom: 2px; }

  /* 普通用户会话块 */
  .session-block { border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 16px; overflow: hidden; }
  .session-header { padding: 10px 14px; background: #fafafa; font-weight: 600;
    display: flex; justify-content: space-between; align-items: center; }
  .session-content { padding: 14px; }
  .session-content .section-title { font-weight: 600; color: #555; margin: 10px 0 6px; font-size: 13px; }

  /* Baseline 专用样式 — 蓝色调、虚线边框、更宽间距 */
  .session-block.baseline-block {
    border: 2px dashed #90CAF9;
    background: #F5F9FF;
    margin-bottom: 24px;
  }
  .session-block.baseline-block .baseline-header {
    background: #E3F2FD;
    border-bottom: 1px dashed #90CAF9;
  }

  .baseline-note {
    font-size: 12px;
    color: #546E7A;
    background: #E3F2FD;
    padding: 8px 12px;
    border-radius: 4px;
    margin-bottom: 10px;
    border-left: 3px solid #1565C0;
  }

  .meta-info { font-size: 12px; color: #888; margin-bottom: 6px; }
  .meta-info span { margin-right: 16px; }
  pre { background: #263238; color: #eeffff; padding: 12px 16px; border-radius: 4px; overflow-x: auto;
    font-size: 12px; line-height: 1.5; max-height: 400px; overflow-y: auto; margin: 6px 0; }
  .curl-block { background: #1e1e1e; color: #d4d4d4; }
  .postman-block { background: #263238; color: #eeffff; max-height: 200px; }
  .binary-card { border: 1px solid #b0bec5; border-radius: 6px; margin: 6px 0; overflow: hidden; }
  .binary-card .card-header { background: #eceff1; padding: 8px 14px; font-weight: 600; font-size: 13px; color: #37474f;
    border-bottom: 1px solid #cfd8dc; }
  .binary-card .meta-row { padding: 4px 14px; font-size: 12px; display: flex; }
  .binary-card .meta-key { font-weight: 600; color: #546e7a; min-width: 130px; flex-shrink: 0; }
  .binary-card .meta-value { font-family: 'Courier New', monospace; color: #263238; word-break: break-all; }
  .binary-card pre.hex-dump { background: #1a1a2e; color: #a8d8ea; font-size: 11px; max-height: 300px; border-radius: 0 0 4px 4px; }
  .binary-card details.base64-section summary { padding: 6px 14px; background: #e8eaf6; cursor: pointer; font-size: 12px; font-weight: 600; color: #283593; }
  .binary-card details.base64-section pre { border-radius: 0; max-height: 200px; }
  .multipart-part { border: 1px dashed #90a4ae; border-radius: 4px; margin: 6px 14px; }
  .multipart-part .part-header { padding: 4px 10px; background: #f5f5f5; font-size: 12px; font-weight: 600; color: #546e7a; }
  .multipart-part pre { border-radius: 0 0 4px 4px; margin: 0; }
  .multipart-binary-part { background: #fff8e1; border-color: #ffb74d; }
  .multipart-binary-part .part-header { background: #fff3e0; color: #e65100; }
  .endpoint-list ol { padding-left: 28px; }
  .endpoint-list li { padding: 4px 0; font-family: 'Courier New', Consolas, monospace; font-size: 13px; }
  .escalated-item { color: #d32f2f; font-weight: 600; }
  .error-item { color: #f57c00; font-weight: 600; }
  .safe-item { color: #2e7d32; font-weight: 600; }
  @media print { body { background: white; padding: 0; } .card { box-shadow: none; border: 1px solid #ddd; } }
</style>
