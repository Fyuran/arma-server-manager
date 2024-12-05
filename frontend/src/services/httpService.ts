import axios from "axios";
import {toast} from "material-react-toastify";

// Add CSRF token to all requests
axios.defaults.xsrfHeaderName = "X-XSRF-TOKEN";
axios.defaults.xsrfCookieName = "XSRF-TOKEN";
axios.defaults.withCredentials = true;

axios.interceptors.response.use(undefined, error => {
    const expectedError =
        error.response &&
        error.response.status >= 400 &&
        error.response.status < 500;

    if (!expectedError) {
        console.error(error.response.data.message);
        toast.error("An unexpected error occurred.");
    } else if (error.response.data.message) {
        toast.error(error.response.data.message);
    }

    return Promise.reject(error);
});

function setJwt(jwt: string) {
    if (jwt) {
        axios.defaults.headers.common['Authorization'] = `Bearer ${jwt}`;
    } else {
        delete axios.defaults.headers.common['Authorization'];
    }
}

export default {
    get: axios.get,
    post: axios.post,
    put: axios.put,
    delete: axios.delete,
    patch: axios.patch,
    setJwt
};
