module.exports=function(t){var a={};function e(s){if(a[s])return a[s].exports;var n=a[s]={i:s,l:!1,exports:{}};return t[s].call(n.exports,n,n.exports,e),n.l=!0,n.exports}return e.m=t,e.c=a,e.d=function(t,a,s){e.o(t,a)||Object.defineProperty(t,a,{enumerable:!0,get:s})},e.r=function(t){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},e.t=function(t,a){if(1&a&&(t=e(t)),8&a)return t;if(4&a&&"object"==typeof t&&t&&t.__esModule)return t;var s=Object.create(null);if(e.r(s),Object.defineProperty(s,"default",{enumerable:!0,value:t}),2&a&&"string"!=typeof t)for(var n in t)e.d(s,n,function(a){return t[a]}.bind(null,n));return s},e.n=function(t){var a=t&&t.__esModule?function(){return t.default}:function(){return t};return e.d(a,"a",a),a},e.o=function(t,a){return Object.prototype.hasOwnProperty.call(t,a)},e.p="",e(e.s=9)}({5:function(t,a){app.initializers.add("askvortsov/saml",(function(){app.extensionData.for("askvortsov-saml").registerSetting((function(){return m("p",null,"Make sure that either the metadata url or the metadata is filled in.")})).registerSetting({setting:"askvortsov-saml-metadata_url",label:app.translator.trans("askvortsov-saml.admin.labels.idp_metadata_url"),type:"text"}).registerSetting({setting:"askvortsov-saml-metadata",label:app.translator.trans("askvortsov-saml.admin.labels.idp_metadata"),type:"text"}).registerSetting({setting:"askvortsov-saml.nameid_format",label:app.translator.trans("askvortsov-saml.admin.labels.nameid_format"),type:"select",options:{"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent":app.translator.trans("askvortsov-saml.admin.options.nameid_format.persistent"),"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress":app.translator.trans("askvortsov-saml.admin.options.nameid_format.emailAddress"),"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified":app.translator.trans("askvortsov-saml.admin.options.nameid_format.unspecified")}}).registerSetting({setting:"askvortsov-saml.want_assertions_signed",label:app.translator.trans("askvortsov-saml.admin.labels.want_assertions_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.want_messages_signed",label:app.translator.trans("askvortsov-saml.admin.labels.want_messages_signed"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.only_option",label:app.translator.trans("askvortsov-saml.admin.labels.only_option"),type:"boolean"}).registerSetting({setting:"askvortsov-saml.sync_attributes",label:app.translator.trans("askvortsov-saml.admin.labels.sync_attributes"),type:"boolean"})}))},9:function(t,a,e){"use strict";e.r(a);var s=e(5);for(var n in s)"default"!==n&&function(t){e.d(a,t,(function(){return s[t]}))}(n)}});
//# sourceMappingURL=admin.js.map