cat bin/sublst/all.txt $1 > temp.txt
sort -u temp.txt -o all.txt
rm bin/sublst/all.txt
rm temp.txt
mv all.txt bin/sublst/all.txt
