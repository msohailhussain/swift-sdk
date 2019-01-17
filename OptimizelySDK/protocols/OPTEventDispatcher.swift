/****************************************************************************
* Copyright 2019, Optimizely, Inc. and contributors                        *
*                                                                          *
* Licensed under the Apache License, Version 2.0 (the "License");          *
* you may not use this file except in compliance with the License.         *
* You may obtain a copy of the License at                                  *
*                                                                          *
*    http://www.apache.org/licenses/LICENSE-2.0                            *
*                                                                          *
* Unless required by applicable law or agreed to in writing, software      *
* distributed under the License is distributed on an "AS IS" BASIS,        *
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. *
* See the License for the specific language governing permissions and      *
* limitations under the License.                                           *
***************************************************************************/

import Foundation

public typealias DispatchCompletionHandler = (Result<Data, OPTEventDispatchError>)->(Void)

public class OPTEventDispatchError : Error {
    public var localizedDescription: String
    
    init(description:String) {
        localizedDescription = description
    }
}

/**
 The OPTEventDispatcher dispatches events to the Optimizely backend used in results.
 */
public protocol OPTEventDispatcher {
    static func createInstance() -> OPTEventDispatcher?
    /**
     Dispatch event to Optimizely backend for results measurement.
     - Parameter event: EventForDispatch object which contains the url to send to and the body.
     - Parameter completionHandler: Called when the event has been sent or if an error occured.  This may not be called in the case where the dispatcher is doing batch events. It is up to the implementor of the protocol.
    */
    func dispatchEvent(event:EventForDispatch, completionHandler: @escaping DispatchCompletionHandler)
}