class Role{
    public id: any
    public name: string
    public permissions: []

    constructor(roleJson: any){
        if(roleJson != undefined && roleJson != null && roleJson._id != undefined && roleJson._id != null && roleJson.name != undefined && roleJson.name != null && roleJson.permissions != undefined && roleJson.permissions != null){
            this.id = roleJson._id;
            this.name = roleJson.name;
            this.permissions = roleJson.permissions;
        }
    }

    setOrAddPermission(permissionName: string, value: boolean): void{
        //TODO
    }
    removePermission(permissionName: string): void{
        //TODO
    }
}
export { Role }