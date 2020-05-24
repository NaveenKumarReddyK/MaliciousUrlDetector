# Malicious URL Detector

## API's
``` Start API server ```
> node MalwareAPI

Get Links that are embeded in an ` URL `
> http://localhost:4000/gethrefs
> Type your url in ` urlName ` field (if you are uisng Post Man)

Get result of ` URL Void ` scanner
> http://localhost:4000/urlvoidresult
> Type your url in ` urlVoidurl ` field (if you are uisng Post Man)

Get result of ` VIrus Total ` scanner
Use your own api in Line 50 of MalwareAPI.js
> http://localhost:4000/vtapi
> Type your url in ` vtUrl ` field (if you are uisng Post Man)

Get result of ` MetaDefender ` scanner
> http://localhost:4000/metadscan
> Type your url in ` metaScanUrl ` field (if you are uisng Post Man)

## URL Score Finder
``` Start Server ```
> node URLScore

Get Full Score of all links in a given ` URL `

> http://localhost:4000/fullscan
> Type url in  `fullScanUrl ` field
 All the details are displayed in console


