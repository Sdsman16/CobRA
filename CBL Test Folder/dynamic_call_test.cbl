IDENTIFICATION DIVISION.
       PROGRAM-ID. DynamicCallTest.
      * Test dynamic call vulnerabilities (CobRA's Dynamic Call rule)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 PROGRAM-NAME PIC X(20).
       PROCEDURE DIVISION.
      * Dynamic CALL with unvalidated input
           ACCEPT PROGRAM-NAME.
           CALL PROGRAM-NAME.
           DISPLAY "Called: " PROGRAM-NAME.
           MOVE "EXTERNAL-PROG" TO PROGRAM-NAME.
           CALL PROGRAM-NAME.
           STOP RUN.