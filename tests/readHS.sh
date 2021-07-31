for f in cf*.txt
do
	#echo "File name is $f"
	while IFS= read -r line
	do
		if [[ "$line" == "Handshake complete with role :DTLS_CLIENT and hs_rtt:"* ]]; then
			echo "$line" | awk '{ print $8, $11 }'
		fi
	done < $f
done

# bash runreadfileHS.sh
# Reading files to recover only hs_rtt from all files

