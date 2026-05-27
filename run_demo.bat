@echo off
cls
color 0A

echo ======================================================================
echo           SEILX FORENSIC EVIDENCE INTEGRITY DEMO
echo ======================================================================
echo.
echo [SCENARIO 1] Valid Compositional Chain (Layer 1 x Layer 3)
echo Verifying untampered production state with authentic upstream anchors...
echo.
py seilx_verify.py verify examples/seilx-bundle-with-upstream.seilx --pubkey test_keys/seilx_test_public.pem --upstream examples/rtk-evidence-mock.json --upstream-pubkey test_keys/rtk_mock_public.pem --report executive
echo.
echo Executive report saved to: seilx_report.txt
echo.
pause

cls
color 0C

echo ======================================================================
echo [SCENARIO 2] Post-Decision Tampering (Layer 3 Breach)
echo Simulating unauthorized byte manipulation in decision-state...
echo.
py seilx_verify.py verify examples/tampered-hash-bundle.seilx --pubkey test_keys/seilx_test_public.pem --upstream examples/rtk-evidence-mock.json --upstream-pubkey test_keys/rtk_mock_public.pem --report executive
echo.
echo Executive report saved to: seilx_report.txt
echo.
pause

cls
color 0E

echo ======================================================================
echo [SCENARIO 3] Upstream Mandate Tampering (Layer 1 Supply Chain Attack)
echo Verifying against tampered RTK-1 evidence object...
echo.
py seilx_verify.py verify examples/seilx-bundle-with-upstream.seilx --pubkey test_keys/seilx_test_public.pem --upstream examples/rtk-evidence-TAMPERED.json --upstream-pubkey test_keys/rtk_mock_public.pem --report executive
echo.
echo ======================================================================
echo         DEMO COMPLETE -- FORENSIC ENFORCEMENT LIVE
echo ======================================================================
echo.
pause
