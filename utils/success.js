export const createSuccess = (statusCode, successMessage, data) =>{
    const successObject = {
        status : statusCode,
        message : successMessage,
        data : data
        
    }
    return successObject;   
}