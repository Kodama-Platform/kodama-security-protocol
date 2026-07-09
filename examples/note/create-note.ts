import { createNotePayload } from "@kodama/ksp-core";
const result = await createNotePayload({ 
    slug: "wallet", 
    password: "replace-with-user-password", 
    plaintext: "My private note",
    productType: "note"
});
console.log(result.payload);
console.log(
    "Save client-side only:",
    {
        readerCapability: result.readerCapability,
        editorPrivateKey: result.editorPrivateKey,
        ownerPrivateKey: result.ownerPrivateKey,
    }
);
