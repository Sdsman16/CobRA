IDENTIFICATION DIVISION.
       PROGRAM-ID. AuthenticationTest.
      * Test authentication vulnerabilities (e.g., CVE-2023-4501)
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01 USER-ID PIC X(20).
       01 PASSWORD PIC X(20).
       01 INPUT-BUFFER PIC X(30).
       PROCEDURE DIVISION.
      * Weak authentication constructs
           ACCEPT USER-ID.
           DISPLAY "User ID: " USER-ID.
           ACCEPT PASSWORD FROM CONSOLE.
           DISPLAY "Password: " PASSWORD.
           ACCEPT INPUT-BUFFER.
           IF INPUT-BUFFER = "USERNAME" OR INPUT-BUFFER = "PASSWORD"
               DISPLAY "Access Granted"
           END-IF.
           STOP RUN.