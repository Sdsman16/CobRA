IDENTIFICATION DIVISION.
       PROGRAM-ID. UnvalidatedInputTest.
      * Test unvalidated input vulnerabilities (CobRA's Unvalidated Input rule)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 INPUT-BUFFER PIC X(5).
       01 ANOTHER-BUFFER PIC X(10).
       PROCEDURE DIVISION.
      * Unvalidated ACCEPT statements
           ACCEPT INPUT-BUFFER.
           DISPLAY "Input: " INPUT-BUFFER.
           ACCEPT ANOTHER-BUFFER FROM CONSOLE.
           DISPLAY "Another Input: " ANOTHER-BUFFER.
           STOP RUN.