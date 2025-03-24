import { IconLoader } from "@tabler/icons-react";

export default function Spinner() {
    return (
        <div className="flex py-6 justify-center items-cente">
            <IconLoader size={70} className="opacity-50 animate-spin" />
        </div>
    );
}
