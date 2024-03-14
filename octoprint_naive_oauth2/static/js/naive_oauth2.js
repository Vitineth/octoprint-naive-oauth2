/*
 * View model for OctoPrint-Naive-OAuth2
 *
 * Author: Ryan Delaney
 * License: AGPLv3
 */
(function (global, factory) {
    if (typeof define === "function" && define.amd) {
        define(["OctoPrintClient", "jquery"], factory);
    } else {
        factory(global.OctoPrintClient, global.$);
    }
})(this, function (OctoPrintClient, $) {
    var url = "api/oauth";

    var OctoPrintOauthClient = function (base) {
        this.base = base;
    };

    OctoPrintOauthClient.prototype.getLoginUrl = function () {
        return this.base.get("plugin/naive_oauth2/oauth/url").then(function (settings, statusText, request) {
            console.log(settings.url, statusText, request);
            return settings.url;
        });
    }

    OctoPrintClient.registerComponent("oauth", OctoPrintOauthClient);
    return OctoPrintOauthClient;
});

$(function () {
    const oauthButton = $("#oauth-button");

    oauthButton.click(function () {
        OctoPrint.oauth.getLoginUrl().then((url) => {
            window.location.href = url;
        });
    });
})
