bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"
bridge LZCopy, 3001, 4
