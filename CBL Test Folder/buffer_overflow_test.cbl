IDENTIFICATION DIVISION.
       PROGRAM-ID. BufferOverflowTest.
      * Test buffer overflow vulnerabilities (e.g., CVE-2019-14468, CVE-2019-16395)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 MY-ARRAY OCCURS 5 TIMES PIC X(10).
       01 LARGE-BUFFER PIC X(100).
       01 INDEX-VAR PIC 9(4) VALUE 10.
       PROCEDURE DIVISION.
      * Risky array access beyond bounds
           MOVE "OVERFLOW-DATA" TO MY-ARRAY(INDEX-VAR).
      * Large MOVE to trigger potential compiler overflow
           MOVE "VERY-LONG-DATA-REPEATED-TO-FILL-BUFFER-1234567890" TO LARGE-BUFFER.
           DISPLAY LARGE-BUFFER.
           PERFORM VARYING INDEX-VAR FROM 1 BY 1 UNTIL INDEX-VAR > 10
               MOVE "TEST" TO MY-ARRAY(INDEX-VAR)
           END-PERFORM.
           STOP RUN.