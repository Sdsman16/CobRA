IDENTIFICATION DIVISION.
       PROGRAM-ID. HardcodedValueTest.
      * Test hardcoded value vulnerabilities (CobRA's Hardcoded Value rule)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 SECRET-KEY PIC X(20).
       01 CONFIG-VALUE PIC X(30).
       PROCEDURE DIVISION.
      * Hardcoded sensitive data
           MOVE "SECRET12345" TO SECRET-KEY.
           DISPLAY "Key: " SECRET-KEY.
           MOVE "CONFIG-DATA-SECURE" TO CONFIG-VALUE.
           DISPLAY "Config: " CONFIG-VALUE.
           STOP RUN.