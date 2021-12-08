import { Role } from './Role.js';

class User{
    public id: any
    public name: string
    public email: string
    public hash: (string | null)
    public permissions: []

    constructor(name: string, email: string, hash: (string | null), permissions: []){
        this.name = name;
        this.email = email;
        this.hash = hash;
        this.permissions = permissions;
    }

    setPermissionFromRole(role: Role): void{
        this.permissions = role.permissions;
    }
    setOrAddPermission(permissionName: string, value: boolean): void{
        //TODO
    }
    removePermission(permissionName: string): void{
        //TODO
    }
}
export { User }