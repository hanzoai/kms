cd "kms-standalone"
helm dependency update
helm package .
for i in *.tgz; do
    [ -f "$i" ] || break
    cloudsmith push helm --republish hanzoai/kms-helm-charts "$i"
done
cd ..
