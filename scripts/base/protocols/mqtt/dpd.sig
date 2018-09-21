signature dpd_mqtt {
   ip-proto == tcp
   payload /^.{4,7}MQ/
   enable "mqtt"
}
