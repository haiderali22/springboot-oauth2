
# Harsicorp consul Docker
docker run -d -p 8500:8500 -p 8600:8600/udp --name=oauth-counsal hashicorp/consul agent -server -ui -node=server-1 -bootstrap-expect=1 -client=0.0.0.0



Open ui as 
http://127.0.0.1:3000/