"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
const core_1 = require("@angular/core");
const http_1 = require("@angular/http");
require("rxjs/add/operator/toPromise");
require("rxjs/add/operator/map");
require("rxjs/add/operator/catch");
let TutorRepository = class TutorRepository {
    constructor(http) {
        this.http = http;
        // private _apiUrl = 'api/tutors';
        this._apiUrl = 'http://52.27.67.68/testingdallastutors/public/index.php/tutor/signup';
    }
    getData(response) {
        let body = response.json();
        console.log('response', body);
        return body.data || body;
    }
    //  public signUp(user: any): Promise<Tutor> {
    // 	return this.http
    // 	.post(this._apiUrl, user)
    // 	.toPromise()
    // 	.then(this.getData)
    // 	.catch(x => x.message);
    // }
    signUp(user) {
        let headers = new http_1.Headers({ 'Content-Type': 'application/json', 'Accept': 'q=0.8;application/json;q=0.9' });
        let options = new http_1.RequestOptions({ headers: headers });
        return this.http.post(this._apiUrl, options)
            .map((res) => res.json() || {})
            .catch((error, caught) => {
            console.error(error.json().error || 'Server error');
            return caught;
        });
    }
    // send(user: any): Promise<Tutor> {
    // 	return this.http
    // 	.post(this._apiUrl, user)
    // 	.toPromise()
    // 	.then(this.getData)
    // 	.catch(x => x.message);
    // }
    getAll() {
        let headers = new http_1.Headers({ 'Content-Type': 'application/json', 'Accept': 'q=0.8;application/json;q=0.9' });
        let options = new http_1.RequestOptions({ headers: headers });
        return this.http.get('http://52.27.67.68/testingdallastutors/public/index.php/alltutors', options)
            .map((res) => res.json() || {})
            .catch((error, caught) => {
            console.error(error.json().error || 'Server error');
            return caught;
        });
    }
    findTutor() {
        return this.http.get('http://52.27.67.68/testingdallastutors/public/index.php/findTutor')
            .map((res) => res.json() || {})
            .catch((error, caught) => {
            console.error(error.json().error || 'Server error');
            return caught;
        });
    }
    listAll() {
        return this.http
            .get(this._apiUrl)
            .toPromise()
            .then(x => x.json().data)
            .catch(x => x.message);
    }
    getById(id) {
        return this.http
            .get(`${this._apiUrl}/${id}`)
            .toPromise()
            .then(x => x.json().data)
            .catch(x => x.message);
    }
    add(tutor) {
        return this.http
            .post(this._apiUrl, tutor)
            .toPromise()
            .then(x => x.json().data)
            .catch(x => x.message);
    }
    update(tutor) {
        return this.http
            .put(`${this._apiUrl}/${tutor.id}`, tutor)
            .toPromise()
            .then(() => tutor)
            .catch(x => x.message);
    }
    delete(tutor) {
        return this.http
            .delete(`${this._apiUrl}/${tutor.id}`)
            .toPromise()
            .catch(x => x.message);
    }
    addCourse(course) {
        this.tutor.courses.push(course);
    }
    getIndex(val) {
        for (var i = this.tutor.courses.length; i--;) {
            var course = this.tutor.courses[i];
            if (course == val)
                return i;
        }
        return -1;
    }
    deleteCourse(course) {
        var index = this.getIndex(course);
        this.tutor.courses.splice(index, 1);
    }
    create(tutor) {
        return this.http.post(this._apiUrl, tutor, this.jwt()).map((response) => response.json());
    }
    jwt() {
        // create authorization header with jwt token
        let currentUser = JSON.parse(localStorage.getItem('currentUser'));
        if (currentUser && currentUser.token) {
            let headers = new http_1.Headers({ 'Authorization': 'Bearer ' + currentUser.token });
            return new http_1.RequestOptions({ headers: headers });
        }
    }
};
TutorRepository = __decorate([
    core_1.Injectable(),
    __metadata("design:paramtypes", [http_1.Http])
], TutorRepository);
exports.TutorRepository = TutorRepository;
//# sourceMappingURL=tutor-repository.service.js.map