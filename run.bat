@ECHO OFF

mkdir path
mkdir build
mkdir generated

cd path

echo 123  > a.txt
echo asd  > b.txt
echo temp > c.txt

cd ..
javac -XDignore.symbol.file -d build Ichecker.java
cd build

echo executed command: createCert
java Ichecker createCert -k ../generated/private.key -c ../generated/certificate.crt
echo executed command: createReg
java Ichecker createReg -r ../generated/reg.txt -p ../path -l ../generated/log.txt -h SHA-256 -k ../generated/private.key

cd ../path

del a.txt

echo asd > d.txt
echo 123 > b.txt
echo asd > c.txt

cd ../build

echo executed command: check
java Ichecker check -r ../generated/reg.txt -p ../path -l ../generated/log.txt -h SHA-256 -c ../generated/certificate.crt

cd ../generated

echo.
type certificate.crt

echo.

echo -----BEGIN PRIVATE KEY FILE-----
type private.key
echo.
echo -----END PRIVATE KEY FILE-----

echo.

echo -----BEGIN LOG FILE-----
type log.txt
echo -----END LOG FILE-----

echo.

echo -----BEGIN REGISTRY FILE-----
type reg.txt
echo.
echo -----END REGISTRY FILE-----

echo.

cd ..

PAUSE