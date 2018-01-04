#!/bin/bash

#HTML header
cat << headerend
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<style>
body {background-color:#fff8ee;}
table, th, td {
    border: 1px solid #000080;
    border-collapse: collapse;
    padding: 2px;
}
</style>
<title>Traffic statistics</title>
</head>
<body>
<h1>Content</h1>
<ul>
headerend

for i in $*
do
        echo "<li><h3><a href=#$i>$i</a></h3></li>"
done
echo "</ul><br break=all/>"

for i in $*
do
        echo '<div style="overflow: auto;">'
        echo '<div style="float: left; width:50%;" id='$i'><h2>'$i'</h2>'
        echo "<table><tr><th>Count</th><th>Source</th><th>Destination</th><th>Service</th></tr>"
        awk '{print "<tr><td>",$1,"</td><td>",$2,"</td><td>",$3,"</td><td>",$4,"</td></tr>"}' < $i
        echo "</table></div>"

        ips=`echo $i. | sed -e 's/\..*$/.tops/'`
        echo '<div style="float: right;  width:50%;"><h2>'$ips'</h2>'
        echo "<table><tr><th>Count</th><th>Source</th></tr>"
        awk '{print "<tr><td>",$1,"</td><td>",$2,"</td></tr>"}' < $ips
        echo "</table></div>"
        echo "</div><br break=all/>"

done


echo "</body> </html>"
