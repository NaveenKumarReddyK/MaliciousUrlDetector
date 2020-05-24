const express = require("express");
const cheerio = require("cheerio");
const requestUrl = require("request");
const urlParser = require("url");
const fs = require("fs");
const app = express();
const bodyParser = require("body-parser");
const cors = require("cors");

app.use(cors({ credentials: true, origin: "http://localhost:3000" }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/fullscan", function (req, res) {
  const url = req.body.fullScanUrl;

  let bodyhtml;
  let linksJson = [];
  var AHttpLinkIndex = 1;

  requestUrl(url, function (err, hrefResponse, html) {
    if (!err) {
      const $ = cheerio.load(html);

      bodyhtml = html;

      //#################################################################################
      $("a").each(function () {
        let aLink = $(this).attr("href");
      });
      //#################################################################################
      $("img").each(function () {
        let imgSrc;
        imgSrc = $(this).attr("src");
      });

      $("iframe").each(function () {
        let iframeHttp;
        iframeHttp = $(this).attr("src");
        if (iframeHttp !== "") {
        }
      });

      var set = new Set();
      //################################ GET HOST NAMES ONLY #################################################
      $('a[href^="http"]').each(function () {
        let aHttp, cleanUrl;
        // aHttp = $(this).attr("href");
        aHttp = $(this).attr("href");
        const newUrl = urlParser.parse(aHttp);
        cleanUrl = newUrl.host;
        cleanUrl = cleanUrl.replace("www.", "");

        if (!set.has(cleanUrl)) {
          set.add(cleanUrl);

          AHttpLinkIndex += 1;
        }
      });

      var resArray = [];
      //########################### URL VOID SCAN ###############################################

      // setTimeout(() => {
      console.log("############## Result of " + url + " ###############");
      console.log(
        "------------------------ Results of UrlVoid ------------------------ "
      );
      for (let urls of set) {
        const urlVoid = "https://www.urlvoid.com/scan/" + urls;
        requestUrl(urlVoid, function (err, res, urlVoidHtml) {
          if (!err) {
            const $ = cheerio.load(urlVoidHtml);
            let tdVal, resWebStatus;
            tdVal = $("tbody")
              .first()
              .find("tr:nth-child(3) td:nth-child(2)")
              .text();
            tdVal = tdVal.toString();
            tdVal = tdVal.substr(0, tdVal.indexOf("/"));
            if (tdVal >= 0 && tdVal < 5) {
              resWebStatus = "Secure";
            } else if (tdVal >= 5 && tdVal < 15) {
              resWebStatus =
                "Affected with malware but risk is =====> LOW <=====";
            } else if (tdVal >= 15 && tdVal < 20) {
              resWebStatus =
                "Affected with malware but risk is  =====> MODERATE <=====";
            } else if (tdVal > 20) {
              resWebStatus =
                "Affected with malware but risk is  =====> HIGH <=====";
            }
            console.log(
              "Website Name : " +
                urls +
                "       Website Score : " +
                tdVal +
                "          Webiste Status : " +
                resWebStatus
            );
          }
        });
      }
      // }, 1000);

      //#################################################################################

      setTimeout(() => {
        console.log(
          "------------------------Results of Meta Defender  ---------------------"
        );
        for (let urls of set) {
          var options = {
            url: "https://api.metadefender.com/v4/domain/" + urls,
            headers: {
              apikey: "fd6815809853af082e8cdb05daa4b563",
            },
          };

          requestUrl(options, function (error, response, body) {
            // console.log(JSON.stringify(body));
            var resJson = JSON.parse(body);
            var resWebStatus;
            if (resJson.lookup_results.detected_by <= 3) {
              resWebStatus = "Secure";
            } else if (
              resJson.lookup_results.detected_by > 3 &&
              resJson.lookup_results.detected_by <= 5
            ) {
              resWebStatus = "Mildy infected by some virus";
            } else if (resJson.lookup_results.detected_by > 5) {
              resWebStatus = "Unsecure";
            }
            console.log(
              "Website Name :" +
                urls +
                "          Malware Detection rate : " +
                resJson.lookup_results.detected_by +
                "       Website Status : " +
                resWebStatus
            );
            resArray.push({
              "Malware Detction Score": resJson.lookup_results.detected_by,
              "Website Status": resWebStatus,
            });
          });
        }
        res.json(linksJson);
      }, 6000);
    }
  });
});

//########################### VIRUS TOTAL API SCAN ###############################################
app.get("/vtapi", function (req, res) {
  var options = {
    method: "GET",
    url:
      "https://www.virustotal.com/vtapi/v2/url/report?apikey=d5055ddaf9f1345c34cf6dc18f502feaa186ec07223e3bf8178eebeda4547556&resource=" +
      url,
  };
  requestUrl(options, function (error, response, body) {
    var vtRes = JSON.parse(body);
    var positiveCount = vtRes.positives;
    var mlSeverity;
    if (positiveCount < 10) {
      mlSeverity = "LOW";
    } else if (positiveCount >= 10 && positiveCount < 20) {
      mlSeverity = "MODERATE";
    } else if (positiveCount >= 20 && positiveCount < 30) {
      mlSeverity = "HIGH";
    } else if (positiveCount >= 30) {
      mlSeverity = "VERY HIGH";
    }
    console.log(
      "Totally detetced malwares : " +
        positiveCount +
        " Malware Severity : " +
        mlSeverity
    );
    res.json({
      "Totally detetced malwares  ": positiveCount,
      Severity: mlSeverity,
    });
  });
});

//#############################################################################################
app.listen(4000, function (err) {
  if (err) {
    console.log("Error while starting the server");
  }
  console.log("Sucessfully connected to the port 4000");
});
