module.exports=function(t){var a={};function s(e){if(a[e])return a[e].exports;var r=a[e]={i:e,l:!1,exports:{}};return t[e].call(r.exports,r,r.exports,s),r.l=!0,r.exports}return s.m=t,s.c=a,s.d=function(t,a,e){s.o(t,a)||Object.defineProperty(t,a,{enumerable:!0,get:e})},s.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},s.t=function(t,a){if(1&a&&(t=s(t)),8&a)return t;if(4&a&&"object"==typeof t&&t&&t.__esModule)return t;var e=Object.create(null);if(s.r(e),Object.defineProperty(e,"default",{enumerable:!0,value:t}),2&a&&"string"!=typeof t)for(var r in t)s.d(e,r,function(a){return t[a]}.bind(null,r));return e},s.n=function(t){var a=t&&t.__esModule?function(){return t.default}:function(){return t};return s.d(a,"a",a),a},s.o=function(t,a){return Object.prototype.hasOwnProperty.call(t,a)},s.p="",s(s.s=8)}({5:function(t,a){app.initializers.add("askvortsov/saml",(function(){app.extensionData.for("askvortsov-saml").registerSetting((function(){return m("p",null,app.translator.trans("askvortsov-saml.admin.header.text"))})).registerSetting({setting:"askvortsov-saml.idp_metadata_url",label:app.translator.trans("askvortsov-saml.admin.labels.idp_metadata_url"),type:"text"}).registerSetting({setting:"askvortsov-saml.idp_metadata",label:app.translator.trans("askvortsov-saml.admin.labels.idp_metadata"),type:"text"}).registerSetting({setting:"askvortsov-saml.nameid_format",label:app.translator.trans("askvortsov-saml.admin.labels.nameid_format"),type:"select",options:{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":app.translator.trans("askvortsov-saml.admin.options.nameid_format.persistent"),"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":app.translator.trans("askvortsov-saml.admin.options.nameid_format.emailAddress"),"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified":app.translator.trans("askvortsov-saml.admin.options.nameid_format.unspecified")}}).registerSetting({setting:"askvortsov-saml.authn_requests_signed",label:app.translator.trans("askvortsov-saml.admin.labels.authn_requests_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.logout_request_signed",label:app.translator.trans("askvortsov-saml.admin.labels.logout_request_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.logout_response_signed",label:app.translator.trans("askvortsov-saml.admin.labels.logout_response_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.sign_metadata",label:app.translator.trans("askvortsov-saml.admin.labels.sign_metadata"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.want_assertions_encrypted",label:app.translator.trans("askvortsov-saml.admin.labels.want_assertions_encrypted"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.want_assertions_signed",label:app.translator.trans("askvortsov-saml.admin.labels.want_assertions_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.want_messages_signed",label:app.translator.trans("askvortsov-saml.admin.labels.want_messages_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.slo",label:app.translator.trans("askvortsov-saml.admin.labels.slo"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.only_option",label:app.translator.trans("askvortsov-saml.admin.labels.only_option"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.x509_key",label:app.translator.trans("askvortsov-saml.admin.labels.x509_key"),type:"text"}).registerSetting({setting:"askvortsov-saml.x509_cert",label:app.translator.trans("askvortsov-saml.admin.labels.x509_cert"),type:"text"})}))},8:function(t,a,s){"use strict";s.r(a);var e=s(5);for(var r in e)"default"!==r&&function(t){s.d(a,t,(function(){return e[t]}))}(r)}});
//# sourceMappingURL=admin.js.map