/*
 * (C) Copyright 2006-2011 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     bstefanescu
 */
package org.nuxeo.ecm.automation.core.operations.document;

import java.util.Collections;

import org.nuxeo.ecm.automation.core.Constants;
import org.nuxeo.ecm.automation.core.annotations.Context;
import org.nuxeo.ecm.automation.core.annotations.Operation;
import org.nuxeo.ecm.automation.core.annotations.OperationMethod;
import org.nuxeo.ecm.automation.core.annotations.Param;
import org.nuxeo.ecm.automation.core.collectors.DocumentModelCollector;
import org.nuxeo.ecm.core.api.CoreSession;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentRef;
import org.nuxeo.ecm.core.trash.TrashService;

/**
 * @author <a href="mailto:bs@nuxeo.com">Bogdan Stefanescu</a>
 */
@Operation(id = DeleteDocument.ID, category = Constants.CAT_DOCUMENT, label = "Delete", description = "Delete the input document. The previous context input will be restored for the next operation.")
public class DeleteDocument {

    public static final String ID = "Document.Delete";

    @Context
    protected CoreSession session;

    @Context
    protected TrashService trashService;

    @Param(name = "hard", required = false, description = "If false and Trash Service is enabled, document is moved to trash, permanently delete the document otherwise")
    protected boolean hard = false;

    @OperationMethod(collector = DocumentModelCollector.class)
    public DocumentModel run(DocumentRef doc) {
        return run(session.getDocument(doc));
    }

    @OperationMethod(collector = DocumentModelCollector.class)
    public DocumentModel run(DocumentModel doc) {
        if (hard) {
            session.removeDocument(doc.getRef());
            return null;
        } else {
            trashService.trashDocuments(Collections.singletonList(doc));
            // return doc with updated deleted markers
            return session.getDocument(doc.getRef());
        }
    }

}
