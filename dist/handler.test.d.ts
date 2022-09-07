declare const CryptoJS: any;
declare const dbAuthError: any;
declare const handler: any;
declare const DbInterface: any, DbAuthHandler: any;
declare const DbMock: {
    new (accessors: any): {};
};
declare const TableMock: {
    new (accessor: any): {
        count(): any;
        create({ data }: {
            data: any;
        }): any;
        update({ where, data }: {
            where: any;
            data: any;
        }): any;
        findFirst({ where }: {
            where: any;
        }): any;
        findUnique({ where }: {
            where: any;
        }): any;
        findMany({ where }: {
            where: any;
        }): any;
        deleteMany(): any;
    };
};
declare const db: {};
declare const dbInterface: any;
declare const UUID_REGEX: RegExp;
declare const SET_SESSION_REGEX: RegExp;
declare const UTC_DATE_REGEX: RegExp;
declare const LOGOUT_COOKIE = "session=;Expires=Thu, 01 Jan 1970 00:00:00 GMT";
declare const createDbUser: (attributes?: {}) => Promise<any>;
declare const expectLoggedOutResponse: (response: any) => void;
declare const expectLoggedInResponse: (response: any) => void;
declare const encryptToCookie: (data: any) => string;
declare let event: any, context: any, options: any;
