
#!/bin/sh
echo "sending data ..."
curl -X POST http://localhost:2001/send \
   -H 'Content-Type: application/json' \
   -d '{"message":"something happened","timestamp":"2022-02-20T10:00:00Z","session_id":"432432","custom":"somedata","user_id":"someuser","component":"componentX","log_level":"info"}'
echo $'\n\ndone'
