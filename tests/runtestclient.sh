for i in $(seq 1 50)
  do 
     echo "Welcome $i times"
	./dtls-client 127.0.0.1 > cf$i.txt
 done


# RUN : sh runtestclient.sh



