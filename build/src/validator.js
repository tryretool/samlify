"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
function verifyTime(utcNotBefore, utcNotOnOrAfter) {
    var now = new Date();
    if (!utcNotBefore && !utcNotOnOrAfter) {
        return true; // throw exception todo
    }
    if (utcNotBefore && !utcNotOnOrAfter) {
        var notBeforeLocal_1 = new Date(utcNotBefore);
        return +notBeforeLocal_1 <= +now;
    }
    if (!utcNotBefore && utcNotOnOrAfter) {
        var notOnOrAfterLocal_1 = new Date(utcNotOnOrAfter);
        return now < notOnOrAfterLocal_1;
    }
    var notBeforeLocal = new Date(utcNotBefore);
    var notOnOrAfterLocal = new Date(utcNotOnOrAfter);
    return +notBeforeLocal <= +now && now < notOnOrAfterLocal;
}
exports.verifyTime = verifyTime;
//# sourceMappingURL=validator.js.map